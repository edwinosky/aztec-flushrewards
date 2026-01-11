# Aztec Flush Reward Sniper 🏹

This bot is designed to snipe the `flushEntryQueue()` function on the Aztec Rewarder contract to claim the 100 $AZTEC reward every epoch (~38.4 minutes).

It uses a sophisticated timing mechanism with interpolated sub-second precision to fire transactions exactly at the epoch transition, bypassing block time limitations.

## Features

- **Interpolated Timing**: Uses local system clock to calculate `T-Minus` with millisecond precision, independent of block arrival times.
- **Smart Sleep (Deep Sleep)**: Automatically sleeps for long durations when the target epoch is far away (>60s) to save resources and reduce RPC spam, waking up 40 seconds before the target.
- **Multi-RPC Support**: Monitors multiple RPC endpoints concurrently to ensure the fastest block data is used.
- **Aggressive Gas Strategy**: Configurable `max_fee` and `priority_fee` to outbid competitors in the public mempool or MEV bundles.
- **Burst Mode**: Increases firing frequency (up to 20 shots/sec) as the target epoch approaches.

## Prerequisites

- **Rust**: Version 1.92.2 or higher (required for latest dependencies).
- **Ethereum Node**: Access to a fast Ethereum RPC (e.g., MEVBlocker, Ankr, Infura).

## Setup

1. **Clone the repository**.
2. **Environment Variables**:
   Copy the example file:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and fill in your details:
   - `PRIVATE_KEY`: Your wallet's private key (Use a burner wallet!).
   - `WRITE_RPC_x`: URLs for sending transactions (Public or MEV-protected).
   - `READ_RPC_URL`: URL for monitoring chain state (e.g., Infura).

## 🛠️ Installation

Before compiling, you must have **Rust** installed.

1. **Install Rustup** (The Rust installer):
   - **Windows**: Download and run [rustup-init.exe](https://win.rustup.rs/).
   - **Linux/Mac**: Run the following command:
     ```bash
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     ```
2. **Update to the latest version** (Required for this bot):
   ```bash
   rustup update
   ```

## Compilation

To build the optimized release binary:

```bash
cargo build --release
```

## Usage

Run the bot directly from the target folder:

```bash
./target/release/aztec_sniper
```

## Donation 💖

If this bot helps you win rewards and you'd like to support its development, donations are welcome in any token on any EVM chain:

**Address**: `0x21AaBcE94c4e690BF0350EC0c26aE5F4fa8c9B5E`

Good luck getting those flushes! 🚽💰

## Support 💬

If you have any questions or need help setting this up, join my Telegram chat:
👉 **[https://t.me/drainerless](https://t.me/drainerless)**
 or X:
👉 **[Edwin0x0](https://x.com/Edwin0x0)**
