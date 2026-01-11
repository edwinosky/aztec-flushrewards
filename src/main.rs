use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    providers::{Provider, ProviderBuilder},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    primitives::{Address, U256, utils::parse_units, keccak256},
    rpc::types::eth::BlockNumberOrTag,
    consensus::{TxEnvelope, TypedTransaction, Signed, SignableTransaction},
    eips::eip2718::Encodable2718,
};
use dotenv::dotenv;
use eyre::Result;
use std::env;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use serde::Serialize;
use reqwest::Client;

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
        function getSlotDuration() external view returns (uint256);
        function getCurrentSlot() external view returns (uint256);
    }
}

const REWARDER_ADDR: &str = "0x7C9a7130379F1B5dd6e7A53AF84fC0fE32267B65";
const ROLLUP_ADDR: &str = "0x603bb2c05D474794ea97805e8De69bCcFb3bCA12";

#[derive(Serialize)]
struct BundleRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: Vec<BundleParams>,
}

#[derive(Serialize)]
struct BundleParams {
    txs: Vec<String>,
    blockNumber: String,
    minTimestamp: Option<u64>,
    maxTimestamp: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    println!("🚀 STARTING AZTEC SNIPER V2.0 (MEV BUNDLES)...");

    let private_key = env::var("PRIVATE_KEY").expect("Missing PRIVATE_KEY");
    let read_rpc = env::var("READ_RPC_URL").expect("Missing READ_RPC_URL");
    let builder_urls: Vec<String> = env::var("BUILDER_URLS")
        .expect("Missing BUILDER_URLS")
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    // Load dynamic gas configuration
    let max_fee_str = env::var("MAX_FEE_GWEI").unwrap_or("1.0".to_string());
    let priority_fee_str = env::var("PRIORITY_FEE_GWEI").unwrap_or("0.06".to_string());
    let gas_limit_str = env::var("GAS_LIMIT").unwrap_or("160000".to_string());
    let gas_manual: u128 = gas_limit_str.parse().expect("Invalid GAS_LIMIT format");

    let signer: PrivateKeySigner = private_key.parse()?;
    let my_address = signer.address();
    let wallet = EthereumWallet::from(signer.clone());
    
    let read_provider = ProviderBuilder::new().on_http(read_rpc.parse()?);
    
    // We don't need write providers anymore, we send to builders directly.
    let http_client = Client::new();

    let rewarder_addr: Address = REWARDER_ADDR.parse()?;
    let rollup_addr: Address = ROLLUP_ADDR.parse()?;
    let rollup_reader = Rollup::new(rollup_addr, read_provider.clone());
    
    // Use a dummy provider for building txs
    let dummy_provider = ProviderBuilder::new().with_recommended_fillers().wallet(wallet.clone()).on_http(read_rpc.parse()?);
    let w_contract = FlushRewarder::new(rewarder_addr, dummy_provider.clone());

    println!("👁️  Monitor: Active");
    println!("👤 Wallet: {}", my_address);
    println!("🏗️  Builders: {:?}", builder_urls);

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
    let mut last_block_num = 0;
    let mut last_block_received_at = Instant::now();

    loop {
        let mut monitor_data = None;

        match async {
            let block = read_provider.get_block_by_number(BlockNumberOrTag::Latest, false).await?.ok_or_else(|| eyre::eyre!("No block"))?;
            let next_epoch = rollup_reader.getNextFlushableEpoch().call().await?._0;
            let next_epoch_u64 = next_epoch.to_string().parse::<u64>()?;
            
            let target_slot = next_epoch_u64 * slots_per_epoch;
            let target_ts = rollup_reader.getTimestampForSlot(U256::from(target_slot)).call().await?._0;
            let target_ts_u64 = target_ts.to_string().parse::<u64>()?;
            let queue = rollup_reader.getEntryQueueLength().call().await?._0;

            Ok::<(u64, u64, u64, U256, u64), eyre::Error>((block.header.timestamp, next_epoch_u64, target_ts_u64, queue, block.header.number.unwrap()))
        }.await {
            Ok((ts, epoch, target, q, num)) => {
                if ts > last_block_ts {
                    last_block_ts = ts;
                    last_block_num = num;
                    last_block_received_at = Instant::now();
                }
                monitor_data = Some((ts, epoch, target, q, num));
            }
            Err(e) => {
                println!("⚠️ Monitor failed: {}. Retrying...", e);
            }
        }

        if let Some((block_ts, next_epoch, target_ts, queue_u256, current_block_num)) = monitor_data {
            let elapsed_since_block = last_block_received_at.elapsed().as_secs_f64();
            let current_interpolated_ts = block_ts as f64 + elapsed_since_block;
            let time_remaining = target_ts as f64 - current_interpolated_ts;

            if next_epoch > target_epoch_processed {
                target_epoch_processed = 0;
                nonce_fetched = false;
            }

            if time_remaining > 15.0 {
                println!("🎯 Meta Epoch: {} | Cola: {} | T-Minus: {:.1}s", next_epoch, queue_u256, time_remaining);
            }

            // SHOOTING WINDOW: AGGRESSIVE - Start 20s early for maximum builder processing time
            let is_shooting_window = time_remaining <= 20.0 && time_remaining > -5.0;

            if is_shooting_window && queue_u256 > U256::from(0) {
                if !nonce_fetched {
                    match read_provider.get_transaction_count(my_address).await {
                        Ok(n) => {
                            current_nonce = n;
                            nonce_fetched = true;
                            // Lock epoch logic maintained
                            target_epoch_processed = next_epoch;
                            println!("🔒 NONCE LOCKED: {}", current_nonce);
                        },
                        Err(e) => println!("⚠️ Nonce Error: {:?}", e),
                    }
                }

                if nonce_fetched {
                    println!("🚨 BUNDLING {:.1}s (Nonce: {}) 🚨", time_remaining, current_nonce);

                    let priority_u256: U256 = parse_units(&priority_fee_str, "gwei")?.into();
                    let priority: u128 = priority_u256.to::<u128>();
                    let max_fee_u256: U256 = parse_units(&max_fee_str, "gwei")?.into();
                    let max_fee: u128 = max_fee_u256.to::<u128>();

                    // Build raw transaction
                    let tx_builder = w_contract.flushEntryQueue()
                        .max_priority_fee_per_gas(priority)
                        .max_fee_per_gas(max_fee)
                        .gas(gas_manual)
                        .nonce(current_nonce);

                    // We need to build the envelope. Alloy's high-level contract calls are tricky to get raw bytes from directly without sending.
                    // For V2 speed, we can use the `wallet` attached provider to build it but we must capture the envelope.
                    // A trick in Alloy: use `build()` then sign with signer.

                    // Use EthereumWallet to sign request properly
                    let mut tx_req = tx_builder.into_transaction_request();
                    tx_req.from = Some(my_address);
                    tx_req.chain_id = Some(1);

                    let typed_tx = tx_req.build_unsigned()?;
                    // Extract inner first
                    let inner = match typed_tx {
                        TypedTransaction::Eip1559(t) => t,
                        _ => unreachable!("Tx must be EIP1559"),
                    };
                    
                    // Sign manually via hash to bypass trait issues
                    let hash = inner.signature_hash();
                    let signature = signer.sign_hash(&hash).await?;
                    let signed = Signed::new_unchecked(inner, signature, hash);
                    let envelope = TxEnvelope::Eip1559(signed);
                    let encoded = envelope.encoded_2718();
                    let encoded_len = encoded.len();
                    let raw_tx_hex = format!("0x{}", hex::encode(encoded));
                    
                    // Debug: Show transaction details
                    println!("📝 TX Hex Length: {} bytes", encoded_len);
                    println!("📝 TX Hex (first 66 chars): {}...", &raw_tx_hex[..66.min(raw_tx_hex.len())]);

                    // Target Block: Current + 1
                    let target_block = current_block_num + 1;
                    let target_block_hex = format!("0x{:x}", target_block);
                    
                    println!("🎯 Target Block: {} ({})", target_block, target_block_hex);

                    // Send to all builders
                    let client = http_client.clone();
                    let mut handles = vec![];
                    
                    for url in &builder_urls {
                        let bundle = BundleRequest {
                            jsonrpc: "2.0".to_string(),
                            id: 1,
                            method: "eth_sendBundle".to_string(),
                            params: vec![BundleParams {
                                txs: vec![raw_tx_hex.clone()],
                                blockNumber: target_block_hex.clone(),
                                minTimestamp: None,
                                maxTimestamp: None,
                            }],
                        };

                        let u = url.clone();
                        let c = client.clone();
                        let s = signer.clone();
                        let my_addr = my_address;
                        
                        let handle = tokio::spawn(async move {
                            println!("📤 Sending bundle to {}...", u);
                            
                            // Build request
                            let mut request = c.post(&u).json(&bundle);
                            
                            // Add Flashbots signature if this is Flashbots relay
                            if u.contains("flashbots") {
                                // Serialize bundle to JSON
                                let bundle_json = serde_json::to_string(&bundle).unwrap_or_default();
                                
                                // Flashbots requires: raw ECDSA signature of keccak256(body)
                                let body_hash = keccak256(bundle_json.as_bytes());
                                
                                // Sign hash directly (no EIP-191 prefix)
                                match s.sign_hash(&body_hash).await {
                                    Ok(sig) => {
                                        // Format: {address}:0x{signature}
                                        let sig_hex = hex::encode(sig.as_bytes());
                                        let sig_header = format!("{}:0x{}", my_addr, sig_hex);
                                        request = request.header("X-Flashbots-Signature", sig_header);
                                        println!("🔐 FB sig: raw ECDSA(keccak256)");
                                    }
                                    Err(e) => println!("⚠️ FB sign failed: {}", e),
                                }
                            }
                            
                            match request.send().await {
                                Ok(resp) => {
                                    let status = resp.status();
                                    match resp.text().await {
                                        Ok(body) => {
                                            if status.is_success() {
                                                println!("✅ Builder {} responded: {}", u, body);
                                            } else {
                                                println!("⚠️ Builder {} returned {}: {}", u, status, body);
                                            }
                                        }
                                        Err(e) => println!("⚠️ Builder {} status {}, couldn't read body: {}", u, status, e),
                                    }
                                },
                                Err(e) => println!("❌ Bundle send failed to {}: {}", u, e),
                            }
                        });
                        handles.push(handle);
                    }
                    
                    // Wait for all builder responses (with timeout)
                    let timeout_duration = Duration::from_secs(2);
                    for handle in handles {
                        let _ = tokio::time::timeout(timeout_duration, handle).await;
                    }

                    // Burst logic: ALWAYS use 100ms for maximum bundle submission frequency
                    let wait_ms = 100;
                    sleep(Duration::from_millis(wait_ms)).await;

                }
            } else {
                 if time_remaining > 60.0 {
                    let deep_sleep_duration = time_remaining - 40.0;
                    if deep_sleep_duration > 0.0 {
                        let sleep_duration_u64 = deep_sleep_duration as u64;
                        println!("💤 Deep Sleep for {}s...", sleep_duration_u64);
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
