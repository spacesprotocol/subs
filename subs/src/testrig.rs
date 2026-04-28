//! Test rig module for running bitcoind + spaced in development mode.
//!
//! Manages bitcoind and spaced directly for reliable persistent data across restarts.
//! Unlike spaces_testutil::TestRig which is designed for ephemeral test setups,
//! this module handles proper process lifecycle for persistent data directories.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use spaces_testutil::bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi};
use spaces_testutil::bitcoind::downloaded_exe_path;
use spaces_client::app::App;
use spaces_client::auth::{auth_token_from_creds, http_client_with_auth};
use spaces_client::rpc::RpcClient;
use spaces_wallet::export::WalletExport;
use tokio::sync::broadcast;

const SPACED_RPC_USER: &str = "user";
const SPACED_RPC_PASS: &str = "pass";
const BITCOIN_RPC_AUTH: &str = "-rpcauth=user:70dbb4f60ccc95e154da97a43b7a9d06$00c10a3849edf2f10173e80d0bdadbde793ad9a80e6e6f9f71f978fb5c797343";

fn get_available_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

/// Handle to a running test rig.
pub struct TestRigHandle {
    bitcoind_process: Option<Child>,
    bitcoin_client: Client,
    bitcoin_rpc_url: String,
    spaced_client: spaces_client::jsonrpsee::http_client::HttpClient,
    spaced_shutdown: broadcast::Sender<()>,
    spaced_rpc_url: String,
}

impl TestRigHandle {
    /// Start a test rig with data stored in the specified directory.
    ///
    /// If the directory already contains data from a previous run, it will be reused.
    /// Otherwise, fresh regtest preset data will be copied there.
    pub async fn start(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;

        // Copy preset data if this is a fresh directory
        let bitcoind_dir = data_dir.join("bitcoind");
        if !bitcoind_dir.exists() {
            let preset = spaces_testutil::bitcoin_regtest_data_path()
                .map_err(|e| anyhow!("Failed to get regtest preset path: {}", e))?;
            spaces_testutil::copy_dir_all(&preset, data_dir)
                .map_err(|e| anyhow!("Failed to copy preset data: {}", e))?;
        }

        // Start bitcoind
        let static_dir = bitcoind_dir;
        let (process, client, rpc_url) = tokio::task::spawn_blocking(move || {
            start_bitcoind(&static_dir)
        })
        .await
        .map_err(|e| anyhow!("join error: {}", e))??;

        let bitcoin_rpc_url = rpc_url;
        tracing::info!("bitcoind started at {}", bitcoin_rpc_url);

        // Start spaced in-process
        let spaced_rpc_port = get_available_port()?;
        let spaced_rpc_url = format!("http://127.0.0.1:{}", spaced_rpc_port);
        let spaced_data_dir = data_dir.join("spaced");
        std::fs::create_dir_all(&spaced_data_dir)?;

        let (spaced_shutdown, _) = broadcast::channel::<()>(1);
        let shutdown_clone = spaced_shutdown.clone();

        let args: Vec<String> = vec![
            "spaced".into(),
            "--chain".into(), "regtest".into(),
            "--bitcoin-rpc-url".into(), bitcoin_rpc_url.clone(),
            "--bitcoin-rpc-user".into(), "user".into(),
            "--bitcoin-rpc-password".into(), "password".into(),
            "--block-index-full".into(),
            "--rpc-port".into(), spaced_rpc_port.to_string(),
            "--data-dir".into(), spaced_data_dir.to_string_lossy().to_string(),
            "--rpc-user".into(), SPACED_RPC_USER.into(),
            "--rpc-password".into(), SPACED_RPC_PASS.into(),
        ];

        tokio::spawn(async move {
            let mut app = App::new(shutdown_clone);
            if let Err(e) = app.run(args).await {
                tracing::error!("spaced exited with error: {}", e);
            }
        });

        // Create RPC client and wait for spaced to be ready
        let auth_token = auth_token_from_creds(SPACED_RPC_USER, SPACED_RPC_PASS);
        let spaced_client = http_client_with_auth(&spaced_rpc_url, &auth_token)
            .map_err(|e| anyhow!("Failed to create spaced RPC client: {}", e))?;

        for i in 0..100 {
            if spaced_client.get_server_info().await.is_ok() {
                tracing::info!("spaced ready after {}ms", i * 100);
                break;
            }
            if i == 99 {
                return Err(anyhow!("spaced did not become ready within 10s"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Load wallets
        let wallets_dir = data_dir.join("wallets");
        if wallets_dir.exists() {
            load_wallets(&spaced_client, &wallets_dir).await?;
        }

        tracing::info!("spaced syncing in background...");

        Ok(Self {
            bitcoind_process: Some(process),
            bitcoin_client: client,
            bitcoin_rpc_url,
            spaced_client,
            spaced_shutdown,
            spaced_rpc_url,
        })
    }

    /// Get the spaced RPC URL.
    pub fn spaced_rpc_url(&self) -> &str {
        &self.spaced_rpc_url
    }

    /// Get the bitcoin RPC URL.
    pub fn bitcoin_rpc_url(&self) -> &str {
        &self.bitcoin_rpc_url
    }

    /// Wait until spaced tip == bitcoind tip.
    pub async fn wait_until_synced(&self) -> Result<()> {
        loop {
            let info = self.spaced_client.get_server_info().await
                .map_err(|e| anyhow!("get_server_info: {}", e))?;

            // bitcoincore_rpc::Client isn't Send, so we can't move it into spawn_blocking.
            // Use a direct call since get_block_count is fast.
            let count = self.bitcoin_client.get_block_count()
                .map_err(|e| anyhow!("get_block_count: {}", e))? as u32;

            if count == info.tip.height {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Gracefully stop bitcoind and spaced, flushing all data to disk.
    pub async fn stop(&mut self) -> Result<()> {
        // Shut down spaced first
        tracing::info!("Stopping spaced...");
        let _ = self.spaced_shutdown.send(());
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Stop bitcoind: RPC stop + wait for process exit
        tracing::info!("Stopping bitcoind...");
        let _ = self.bitcoin_client.stop();

        if let Some(mut process) = self.bitcoind_process.take() {
            // Wait for the process to actually exit (up to 30s)
            for _ in 0..300 {
                if let Some(_status) = process.try_wait()? {
                    tracing::info!("bitcoind exited cleanly");
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            tracing::warn!("bitcoind did not exit within 30s, killing");
            let _ = process.kill();
            let _ = process.wait();
        }

        tracing::info!("Test rig stopped");
        Ok(())
    }

    /// Mine blocks (useful for testing).
    pub async fn mine_blocks(&self, count: usize) -> Result<()> {
        let addr = self.bitcoin_client.get_new_address(None, None)
            .map_err(|e| anyhow!("get_new_address: {}", e))?
            .assume_checked();
        self.bitcoin_client.generate_to_address(count as u64, &addr)
            .map_err(|e| anyhow!("generate_to_address: {}", e))?;

        self.wait_until_synced().await?;
        Ok(())
    }

    /// Start a certrelay instance connected to this test rig's spaced.
    pub async fn start_certrelay(
        &self,
        data_dir: &Path,
        port: u16,
    ) -> Result<(String, broadcast::Sender<()>)> {
        let certrelay_dir = data_dir.join("certrelay");
        std::fs::create_dir_all(&certrelay_dir)?;

        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let url = format!("http://127.0.0.1:{}", port);

        let args = vec![
            "certrelay".to_string(),
            "--chain".to_string(),
            "regtest".to_string(),
            "--data-dir".to_string(),
            certrelay_dir.to_string_lossy().to_string(),
            "--spaced-rpc-url".to_string(),
            self.spaced_rpc_url.replace("://", "://user:pass@"),
            "--port".to_string(),
            port.to_string(),
            "--self-url".to_string(),
            url.clone(),
            "--is-bootstrap".to_string(),
            "--anchor-refresh".to_string(),
            "1".to_string(),
        ];

        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = relay::app::run(args, tx).await {
                tracing::error!("Certrelay exited with error: {}", e);
            }
        });

        tracing::info!("Certrelay started on {}", url);
        Ok((url, shutdown_tx))
    }
}

impl Drop for TestRigHandle {
    fn drop(&mut self) {
        // Best-effort cleanup if stop() wasn't called
        let _ = self.spaced_shutdown.send(());
        let _ = self.bitcoin_client.stop();
        if let Some(mut process) = self.bitcoind_process.take() {
            // Give it a moment to flush
            std::thread::sleep(Duration::from_millis(2000));
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

/// Start bitcoind process and return (process, rpc_client, rpc_url).
fn start_bitcoind(data_dir: &Path) -> Result<(Child, Client, String)> {
    let exe = downloaded_exe_path()
        .map_err(|e| anyhow!("Failed to get bitcoind executable: {}", e))?;

    let rpc_port = get_available_port()?;
    let rpc_url = format!("http://127.0.0.1:{}", rpc_port);
    let datadir_arg = format!("-datadir={}", data_dir.display());
    let rpc_arg = format!("-rpcport={}", rpc_port);

    let mut process = Command::new(&exe)
        .arg(&datadir_arg)
        .arg(&rpc_arg)
        .arg("-regtest")
        .arg("-txindex=1")
        .arg("-dbcache=0")
        .arg("-rpcworkqueue=100")
        .arg("-fallbackfee=0.0001")
        .arg("-listen=0")
        .arg(BITCOIN_RPC_AUTH)
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn bitcoind: {}", e))?;

    // Wait for bitcoind to be ready
    let cookie_file = data_dir.join("regtest").join(".cookie");
    let wallet_url = format!("{}/wallet/default", rpc_url);

    for i in 0..100 {
        if let Some(status) = process.try_wait()? {
            return Err(anyhow!("bitcoind exited early with status: {}", status));
        }
        std::thread::sleep(Duration::from_millis(100));

        if let Ok(client) = Client::new(&rpc_url, Auth::CookieFile(cookie_file.clone())) {
            if client.call::<serde_json::Value>("getblockchaininfo", &[]).is_ok() {
                // Create or load default wallet
                if client.create_wallet("default", None, None, None, None).is_err() {
                    let _ = client.load_wallet("default");
                }
                // Connect with wallet URL
                let wallet_client = Client::new(&wallet_url, Auth::CookieFile(cookie_file))?;
                tracing::info!("bitcoind ready after {}ms", (i + 1) * 100);
                return Ok((process, wallet_client, rpc_url));
            }
        }
    }

    let _ = process.kill();
    Err(anyhow!("bitcoind did not become ready within 10s"))
}

/// Load test wallets into spaced.
async fn load_wallets(
    client: &spaces_client::jsonrpsee::http_client::HttpClient,
    wallets_dir: &Path,
) -> Result<()> {
    for wallet_name in &["wallet_99", "wallet_98"] {
        let wallet_file = wallets_dir.join(format!("{}.json", wallet_name));
        tracing::info!("Loading wallet from: {}", wallet_file.display());

        let json = std::fs::read_to_string(&wallet_file)
            .map_err(|e| anyhow!("Failed to read wallet file {}: {}", wallet_file.display(), e))?;

        let export = WalletExport::from_str(&json)
            .map_err(|e| anyhow!("Failed to parse wallet {}: {}", wallet_name, e))?;

        match client.wallet_import(export).await {
            Ok(_) => tracing::info!("Imported wallet: {}", wallet_name),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("already exists") {
                    tracing::info!("Wallet {} exists, loading...", wallet_name);
                    client.wallet_load(wallet_name).await
                        .map_err(|e| anyhow!("Failed to load wallet {}: {}", wallet_name, e))?;
                    tracing::info!("Loaded wallet: {}", wallet_name);
                } else {
                    return Err(anyhow!("Failed to import wallet {}: {}", wallet_name, e));
                }
            }
        }
    }

    tracing::info!("Wallets loaded, syncing in background...");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_data_persists_across_restarts() {
        let _ = tracing_subscriber::fmt::try_init();

        let data_dir = PathBuf::from("./test-persistence-data");
        let _ = std::fs::remove_dir_all(&data_dir);

        let rounds = 5;
        let blocks_per_round = 5;
        let mut expected_count: Option<u64> = None;

        for i in 0..rounds {
            println!("\n=== Round {}/{} ===", i + 1, rounds);

            let mut handle = TestRigHandle::start(&data_dir).await
                .unwrap_or_else(|e| panic!("start round {} failed: {}", i + 1, e));
            handle.wait_until_synced().await
                .unwrap_or_else(|e| panic!("sync round {} failed: {}", i + 1, e));

            let count = handle.bitcoin_client.get_block_count().unwrap();
            println!("Block count on start: {}", count);

            if let Some(expected) = expected_count {
                assert_eq!(
                    count, expected,
                    "Round {}: block count reset! Expected {} but got {}",
                    i + 1, expected, count
                );
            }

            handle.mine_blocks(blocks_per_round).await
                .unwrap_or_else(|e| panic!("mine round {} failed: {}", i + 1, e));

            let new_count = handle.bitcoin_client.get_block_count().unwrap();
            println!("Block count after mining {}: {}", blocks_per_round, new_count);
            assert_eq!(new_count, count + blocks_per_round as u64);

            expected_count = Some(new_count);

            handle.stop().await
                .unwrap_or_else(|e| panic!("stop round {} failed: {}", i + 1, e));
        }

        println!("\nAll {} rounds passed! Final block count: {}", rounds, expected_count.unwrap());
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
