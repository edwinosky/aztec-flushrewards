use alloy::{
    network::EthereumWallet,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    primitives::{Address, U256, utils::parse_units},
};
// Environment variable management and error handling
use dotenv::dotenv;
use eyre::Result;
use std::env;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use alloy::rpc::types::eth::BlockNumberOrTag;

// --- ABIs ---
sol! {
    #[sol(rpc)]
    contract FlushRewarder {
        function flushEntryQueue() external;
    }

    #[sol(rpc)]
    contract Rollup {
        function getEntryQueueLength() external view returns (uint256);
        function getNextFlushableEpoch() external view returns (uint256);
        function getTimestampForSlot(uint256 _slotNumber) external view returns (uint256);
        function getEpochDuration() external view returns (uint256);
    }
}

const REWARDER_ADDR: &str = "0x7C9a7130379F1B5dd6e7A53AF84fC0fE32267B65";
const ROLLUP_ADDR: &str = "0x603bb2c05D474794ea97805e8De69bCcFb3bCA12";

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    println!("🚀 STARTING AZTEC SNIPER V15.1 (TYPE FIX)...");

    let private_key = env::var("PRIVATE_KEY").expect("Missing PRIVATE_KEY");
    let read_rpc = env::var("READ_RPC_URL").expect("Missing READ_RPC_URL");
    
    let write_rpc_1 = env::var("WRITE_RPC_1").expect("Missing WRITE_RPC_1");
    let write_rpc_2 = env::var("WRITE_RPC_2").expect("Missing WRITE_RPC_2");
    let write_rpc_3 = env::var("WRITE_RPC_3").expect("Missing WRITE_RPC_3");

    // Load dynamic gas configuration or default to aggressive values
    let max_fee_str = env::var("MAX_FEE_GWEI").unwrap_or("1.0".to_string());
    let priority_fee_str = env::var("PRIORITY_FEE_GWEI").unwrap_or("0.06".to_string());
    let gas_limit_str = env::var("GAS_LIMIT").unwrap_or("160000".to_string());
    
    let gas_manual: u128 = gas_limit_str.parse().expect("Invalid GAS_LIMIT format");

    let signer: PrivateKeySigner = private_key.parse()?;
    let my_address = signer.address();
    let wallet = EthereumWallet::from(signer.clone());
    
    let read_provider = ProviderBuilder::new().on_http(read_rpc.parse()?);

    let p1 = ProviderBuilder::new().with_recommended_fillers().wallet(wallet.clone()).on_http(write_rpc_1.parse()?);
    let p2 = ProviderBuilder::new().with_recommended_fillers().wallet(wallet.clone()).on_http(write_rpc_2.parse()?);
    let p3 = ProviderBuilder::new().with_recommended_fillers().wallet(wallet.clone()).on_http(write_rpc_3.parse()?);

    let rewarder_addr: Address = REWARDER_ADDR.parse()?;
    let rollup_addr: Address = ROLLUP_ADDR.parse()?;

    let rollup_reader = Rollup::new(rollup_addr, read_provider.clone());
    
    let w1 = FlushRewarder::new(rewarder_addr, p1.clone());
    let w2 = FlushRewarder::new(rewarder_addr, p2.clone());
    let w3 = FlushRewarder::new(rewarder_addr, p3.clone());

    println!("👁️  Monitor: Active");
    println!("👤 Wallet: {}", my_address);

    let slots_per_epoch = loop {
        match rollup_reader.getEpochDuration().call().await {
            Ok(data) => break data._0.to_string().parse::<u64>()?,
            Err(_) => {
                println!("⚠️ Error connecting monitor. Retrying...");
                sleep(Duration::from_secs(2)).await;
            }
        }
    };
    println!("⚙️ Slots per Epoch: {}", slots_per_epoch);

    let mut current_nonce = 0;
    let mut nonce_fetched = false;
    let mut target_epoch_processed = 0;

    let mut last_block_ts = 0;
    let mut last_block_received_at = Instant::now();

    loop {
        let mut monitor_data = None;

        // Attempt to get the latest block from the main monitor
        match async {
            let block = read_provider.get_block_by_number(BlockNumberOrTag::Latest, false).await?.ok_or_else(|| eyre::eyre!("No block"))?;
            let next_epoch = rollup_reader.getNextFlushableEpoch().call().await?._0;
            let next_epoch_u64 = next_epoch.to_string().parse::<u64>()?;
            
            let target_slot = next_epoch_u64 * slots_per_epoch;
            let target_ts = rollup_reader.getTimestampForSlot(U256::from(target_slot)).call().await?._0;
            let target_ts_u64 = target_ts.to_string().parse::<u64>()?;
            
            let queue = rollup_reader.getEntryQueueLength().call().await?._0;

            Ok::<(u64, u64, u64, U256), eyre::Error>((block.header.timestamp, next_epoch_u64, target_ts_u64, queue))
        }.await {
            Ok((ts, epoch, target, q)) => {
                if ts > last_block_ts {
                    last_block_ts = ts;
                    last_block_received_at = Instant::now();
                }
                monitor_data = Some((ts, epoch, target, q));
            }
            Err(e) => {
                println!("⚠️ Main monitor failed: {}. Retrying...", e);
            }
        }

        if let Some((block_ts, next_epoch, target_ts, queue_u256)) = monitor_data {
            let elapsed_since_block = last_block_received_at.elapsed().as_secs_f64();
            let current_interpolated_ts = block_ts as f64 + elapsed_since_block;
            let time_remaining = target_ts as f64 - current_interpolated_ts;

            if next_epoch > target_epoch_processed {
                target_epoch_processed = 0; // Will be reset below if we shoot
                nonce_fetched = false;
            }

            if time_remaining > 15.0 {
                println!("🎯 Meta Epoch: {} | Cola: {} | T-Minus: {:.1}s", next_epoch, queue_u256, time_remaining);
            }

            // EXPANDED AND AGGRESSIVE WINDOW
            // We start shooting 15 seconds before (approx one block time)
            // Intensity increases as we approach 0.
            let is_shooting_window = time_remaining <= 15.0 && time_remaining > -5.0;

            if is_shooting_window && queue_u256 > U256::from(0) {
                if !nonce_fetched {
                    match read_provider.get_transaction_count(my_address).await {
                        Ok(n) => {
                            current_nonce = n;
                            nonce_fetched = true;
                            println!("🔒 NONCE LOCKED: {}", current_nonce);
                        },
                        Err(e) => println!("⚠️ Nonce Error: {:?}", e),
                    }
                }

                if nonce_fetched {
                    println!("🚨 SHOOTING {:.1}s (Nonce: {}) | RPCs: 3 🚨", time_remaining, current_nonce);

                    let priority_u256: U256 = parse_units(&priority_fee_str, "gwei")?.into();
                    let priority: u128 = priority_u256.to::<u128>();
                    let max_fee_u256: U256 = parse_units(&max_fee_str, "gwei")?.into();
                    let max_fee: u128 = max_fee_u256.to::<u128>();
                    // gas_manual loaded from env at startup

                    let call1 = w1.flushEntryQueue().max_priority_fee_per_gas(priority).max_fee_per_gas(max_fee).gas(gas_manual).nonce(current_nonce);
                    let call2 = w2.flushEntryQueue().max_priority_fee_per_gas(priority).max_fee_per_gas(max_fee).gas(gas_manual).nonce(current_nonce);
                    let call3 = w3.flushEntryQueue().max_priority_fee_per_gas(priority).max_fee_per_gas(max_fee).gas(gas_manual).nonce(current_nonce);

                    let (r1, r2, r3) = tokio::join!(call1.send(), call2.send(), call3.send());

                    let mut success = false;
                    for r in [r1, r2, r3] {
                        match r {
                            Ok(tx) => {
                                println!("✅ SENT: {:?}", tx.tx_hash());
                                success = true;
                            }
                            Err(e) => check_err("Shot", e),
                        }
                    }

                    if success {
                        // If we are very close to the target, shoot at max burst
                        let wait_ms = if time_remaining < 2.0 { 50 } else { 200 };
                        sleep(Duration::from_millis(wait_ms)).await;
                    } else {
                        sleep(Duration::from_millis(10)).await;
                    }
                }
            } else {
                // SMART SLEEP STRATEGY (Deep Sleep)
                if time_remaining > 60.0 {
                    // If more than 60s remaining, sleep until 40s remaining
                    let deep_sleep_duration = time_remaining - 40.0;
                    if deep_sleep_duration > 0.0 {
                        let sleep_duration_u64 = deep_sleep_duration as u64;
                        println!("💤 Deep Sleep for {}s (Wake up at T-40s)...", sleep_duration_u64);
                        sleep(Duration::from_secs(sleep_duration_u64)).await;
                    } else {
                        sleep(Duration::from_secs(1)).await;
                    }
                } else if time_remaining > 30.0 { 
                    sleep(Duration::from_secs(1)).await; 
                } else { 
                    sleep(Duration::from_millis(100)).await; 
                }
            }
        }
    }
}

fn check_err(name: &str, e: alloy::contract::Error) {
    let err = e.to_string();
    if err.contains("already known") || err.contains("duplicate key") {
        println!("🟡 {} ALREADY KNOWN (Good)", name);
    } else if err.contains("Reverted") {
        // Ignore reverts
    } else {
        println!("❌ {} Error: {:?}", name, e);
    }
}
