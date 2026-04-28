use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use bitcoin::ScriptBuf;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use spaces_protocol::slabel::SLabel;
use tokio::task::spawn_blocking;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS chain (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    space BLOB,
    tip_receipt_id INTEGER,
    tip_receipt_groth16_id INTEGER
);

CREATE TABLE IF NOT EXISTS commitments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    idx INTEGER NOT NULL UNIQUE,
    prev_root TEXT,
    root TEXT NOT NULL,
    zk_batch BLOB NOT NULL,
    exclusion_merkle_proof BLOB,
    step_receipt_id INTEGER,
    aggregate_receipt_id INTEGER,
    aggregate_groth16_id INTEGER,
    commit_txid TEXT,
    published_at TEXT,
    estimate TEXT
);

CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS handles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    script_pubkey BLOB NOT NULL,
    commitment_root TEXT,  -- NULL if staged, set to root hex when committed
    commitment_idx INTEGER, -- NULL if staged, set to commitment idx when committed
    publish_status TEXT,   -- NULL = not published, 'temp' = temp cert, 'final' = final cert
    published_temp_at_tip TEXT, -- on-chain tip root when temp cert was issued
    parked INTEGER NOT NULL DEFAULT 0, -- 1 = excluded from next commit
    dev_private_key TEXT   -- testing only: WIF key auto-generated when no script_pubkey provided
);

INSERT OR IGNORE INTO chain (id) VALUES (1);
"#;

#[derive(Debug, Clone)]
pub struct Commitment {
    pub id: i64,
    pub idx: usize,
    pub prev_root: Option<String>,
    pub root: String,
    pub zk_batch: Vec<u8>,
    pub exclusion_merkle_proof: Option<Vec<u8>>,
    pub step_receipt_id: Option<i64>,
    pub aggregate_receipt_id: Option<i64>,
    pub aggregate_groth16_id: Option<i64>,
    /// Txid of the on-chain commit transaction (set after broadcast)
    pub commit_txid: Option<String>,
    /// When final certs for this commitment were published
    pub published_at: Option<String>,
    /// Proving estimate (JSON-serialized EstimateResult)
    pub estimate: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Handle {
    pub id: i64,
    pub name: String,
    pub script_pubkey: Vec<u8>,
    /// NULL if staged, set to commitment root hex when committed
    pub commitment_root: Option<String>,
    /// NULL if staged, set to commitment idx when committed
    pub commitment_idx: Option<usize>,
    /// NULL = not published, "temp" = temp cert published, "final" = final cert published
    pub publish_status: Option<String>,
    /// On-chain tip root when temp cert was issued
    pub published_temp_at_tip: Option<String>,
    /// If true, excluded from next commit_local
    pub parked: bool,
    /// Testing only: WIF private key when auto-generated (not for production use)
    pub dev_private_key: Option<String>,
}

/// Selector for querying handles for publishing.
pub enum HandleSelector {
    /// Handles needing certs: unpublished or temp-published ready for finalization.
    Unpublished(Option<usize>),
    /// Specific committed handles by name (regardless of publish status).
    ByName(Vec<String>),
}

#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let path = path.to_path_buf();
        spawn_blocking(move || Self::open_sync(&path))
            .await?
    }

    pub async fn in_memory() -> anyhow::Result<Self> {
        spawn_blocking(Self::in_memory_sync).await?
    }

    fn open_sync(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    fn in_memory_sync() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    // Chain metadata

    pub async fn get_space(&self) -> anyhow::Result<Option<SLabel>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let space: Option<Vec<u8>> = conn
                .query_row("SELECT space FROM chain WHERE id = 1", [], |row| row.get(0))?;
            match space {
                Some(bytes) => Ok(Some(
                    SLabel::try_from(bytes.as_slice())
                        .map_err(|_| anyhow!("invalid space label in db"))?,
                )),
                None => Ok(None),
            }
        })
        .await?
    }

    pub async fn set_space(&self, space: &SLabel) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let space = space.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE chain SET space = ? WHERE id = 1",
                params![space.as_ref()],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_tip_receipt_id(&self) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            Ok(conn.query_row(
                "SELECT tip_receipt_id FROM chain WHERE id = 1",
                [],
                |row| row.get(0),
            )?)
        })
        .await?
    }

    pub async fn set_tip_receipt_id(&self, id: Option<i64>) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE chain SET tip_receipt_id = ? WHERE id = 1",
                params![id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_tip_groth16_id(&self) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            Ok(conn.query_row(
                "SELECT tip_receipt_groth16_id FROM chain WHERE id = 1",
                [],
                |row| row.get(0),
            )?)
        })
        .await?
    }

    pub async fn set_tip_groth16_id(&self, id: Option<i64>) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE chain SET tip_receipt_groth16_id = ? WHERE id = 1",
                params![id],
            )?;
            Ok(())
        })
        .await?
    }

    // Commitments

    pub async fn commitment_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM commitments", [], |row| row.get(0))?;
            Ok(count as usize)
        })
        .await?
    }

    pub async fn get_commitment(&self, idx: usize) -> anyhow::Result<Option<Commitment>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let commitment = conn
                .query_row(
                    "SELECT id, idx, prev_root, root, zk_batch, exclusion_merkle_proof,
                            step_receipt_id, aggregate_receipt_id, aggregate_groth16_id,
                            commit_txid, published_at, estimate
                     FROM commitments WHERE idx = ?",
                    params![idx as i64],
                    |row| {
                        Ok(Commitment {
                            id: row.get(0)?,
                            idx: row.get::<_, i64>(1)? as usize,
                            prev_root: row.get(2)?,
                            root: row.get(3)?,
                            zk_batch: row.get(4)?,
                            exclusion_merkle_proof: row.get(5)?,
                            step_receipt_id: row.get(6)?,
                            aggregate_receipt_id: row.get(7)?,
                            aggregate_groth16_id: row.get(8)?,
                            commit_txid: row.get(9)?,
                            published_at: row.get(10)?,
                            estimate: row.get(11)?,
                        })
                    },
                )
                .optional()?;
            Ok(commitment)
        })
        .await?
    }

    pub async fn get_last_commitment(&self) -> anyhow::Result<Option<Commitment>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let commitment = conn
                .query_row(
                    "SELECT id, idx, prev_root, root, zk_batch, exclusion_merkle_proof,
                            step_receipt_id, aggregate_receipt_id, aggregate_groth16_id,
                            commit_txid, published_at, estimate
                     FROM commitments ORDER BY idx DESC LIMIT 1",
                    [],
                    |row| {
                        Ok(Commitment {
                            id: row.get(0)?,
                            idx: row.get::<_, i64>(1)? as usize,
                            prev_root: row.get(2)?,
                            root: row.get(3)?,
                            zk_batch: row.get(4)?,
                            exclusion_merkle_proof: row.get(5)?,
                            step_receipt_id: row.get(6)?,
                            aggregate_receipt_id: row.get(7)?,
                            aggregate_groth16_id: row.get(8)?,
                            commit_txid: row.get(9)?,
                            published_at: row.get(10)?,
                            estimate: row.get(11)?,
                        })
                    },
                )
                .optional()?;
            Ok(commitment)
        })
        .await?
    }

    pub async fn get_commitment_by_root(&self, root: &str) -> anyhow::Result<Option<Commitment>> {
        let conn = self.conn.clone();
        let root = root.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let commitment = conn
                .query_row(
                    "SELECT id, idx, prev_root, root, zk_batch, exclusion_merkle_proof,
                            step_receipt_id, aggregate_receipt_id, aggregate_groth16_id,
                            commit_txid, published_at, estimate
                     FROM commitments WHERE root = ?",
                    params![root],
                    |row| {
                        Ok(Commitment {
                            id: row.get(0)?,
                            idx: row.get::<_, i64>(1)? as usize,
                            prev_root: row.get(2)?,
                            root: row.get(3)?,
                            zk_batch: row.get(4)?,
                            exclusion_merkle_proof: row.get(5)?,
                            step_receipt_id: row.get(6)?,
                            aggregate_receipt_id: row.get(7)?,
                            aggregate_groth16_id: row.get(8)?,
                            commit_txid: row.get(9)?,
                            published_at: row.get(10)?,
                            estimate: row.get(11)?,
                        })
                    },
                )
                .optional()?;
            Ok(commitment)
        })
        .await?
    }

    pub async fn list_commitments(&self) -> anyhow::Result<Vec<Commitment>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, idx, prev_root, root, zk_batch, exclusion_merkle_proof,
                        step_receipt_id, aggregate_receipt_id, aggregate_groth16_id,
                        commit_txid, published_at, estimate
                 FROM commitments ORDER BY idx ASC",
            )?;
            let commitments = stmt
                .query_map([], |row| {
                    Ok(Commitment {
                        id: row.get(0)?,
                        idx: row.get::<_, i64>(1)? as usize,
                        prev_root: row.get(2)?,
                        root: row.get(3)?,
                        zk_batch: row.get(4)?,
                        exclusion_merkle_proof: row.get(5)?,
                        step_receipt_id: row.get(6)?,
                        aggregate_receipt_id: row.get(7)?,
                        aggregate_groth16_id: row.get(8)?,
                        commit_txid: row.get(9)?,
                        published_at: row.get(10)?,
                        estimate: row.get(11)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(commitments)
        })
        .await?
    }

    /// Returns (row_id, idx) where idx is the 0-based commitment index
    pub async fn add_commitment(
        &self,
        prev_root: Option<&str>,
        root: &str,
        zk_batch: &[u8],
        exclusion_merkle_proof: Option<&[u8]>,
    ) -> anyhow::Result<(i64, usize)> {
        let conn = self.conn.clone();
        let prev_root = prev_root.map(|s| s.to_string());
        let root = root.to_string();
        let zk_batch = zk_batch.to_vec();
        let exclusion_merkle_proof = exclusion_merkle_proof.map(|b| b.to_vec());
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM commitments", [], |row| row.get(0))?;
            conn.execute(
                "INSERT INTO commitments (idx, prev_root, root, zk_batch, exclusion_merkle_proof)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    count,
                    prev_root,
                    root,
                    zk_batch,
                    exclusion_merkle_proof
                ],
            )?;
            Ok((conn.last_insert_rowid(), count as usize))
        })
        .await?
    }

    pub async fn update_commitment_step_receipt(
        &self,
        commitment_id: i64,
        receipt_id: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET step_receipt_id = ? WHERE id = ?",
                params![receipt_id, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn update_commitment_estimate(
        &self,
        commitment_id: i64,
        estimate_json: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let json = estimate_json.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET estimate = ? WHERE id = ?",
                params![json, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn update_commitment_aggregate_receipt(
        &self,
        commitment_id: i64,
        receipt_id: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET aggregate_receipt_id = ? WHERE id = ?",
                params![receipt_id, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn update_commitment_groth16(
        &self,
        commitment_id: i64,
        receipt_id: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET aggregate_groth16_id = ? WHERE id = ?",
                params![receipt_id, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn update_commitment_txid(
        &self,
        commitment_id: i64,
        txid: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let txid = txid.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET commit_txid = ? WHERE id = ?",
                params![txid, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    // Handles

    /// Add a handle to the handles table (staged, with NULL commitment_root)
    pub async fn add_handle(&self, name: &str, script_pubkey: &[u8], dev_private_key: Option<&str>) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let name = name.to_string();
        let script_pubkey = script_pubkey.to_vec();
        let dev_private_key = dev_private_key.map(|s| s.to_string());
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO handles (name, script_pubkey, commitment_root, dev_private_key) VALUES (?, ?, NULL, ?)",
                params![name, script_pubkey, dev_private_key],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_handle(&self, name: &str) -> anyhow::Result<Option<Handle>> {
        let conn = self.conn.clone();
        let name = name.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let handle = conn
                .query_row(
                    "SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status, published_temp_at_tip, parked, dev_private_key FROM handles WHERE name = ?",
                    params![name],
                    |row| {
                        Ok(Handle {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            script_pubkey: row.get(2)?,
                            commitment_root: row.get(3)?,
                            commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                            publish_status: row.get(5)?,
                            published_temp_at_tip: row.get(6)?,
                            parked: row.get::<_, i64>(7)? != 0,
                            dev_private_key: row.get(8)?,
                        })
                    },
                )
                .optional()?;
            Ok(handle)
        })
        .await?
    }

    pub async fn list_handles(&self) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status, published_temp_at_tip, parked, dev_private_key FROM handles ORDER BY name ASC")?;
            let handles = stmt
                .query_map([], |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                        published_temp_at_tip: row.get(6)?,
                        parked: row.get::<_, i64>(7)? != 0,
                            dev_private_key: row.get(8)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    /// Count total handles
    /// Count handles matching optional search and filter.
    pub async fn handle_count_filtered(
        &self,
        search: Option<String>,
        filter: Option<String>,
    ) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let (where_clause, params) = build_handle_filter(&search, &filter);
            let sql = format!("SELECT COUNT(*) FROM handles{}", where_clause);
            let count: i64 = conn.query_row(&sql, params_from_iter(params.iter().map(|s| s as &dyn rusqlite::types::ToSql)), |row| row.get(0))?;
            Ok(count as usize)
        })
        .await?
    }

    /// List handles with pagination, search, and filter, ordered by most recent first.
    pub async fn list_handles_filtered(
        &self,
        offset: usize,
        limit: usize,
        search: Option<String>,
        filter: Option<String>,
    ) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let (where_clause, mut params) = build_handle_filter(&search, &filter);
            let sql = format!(
                "SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status, published_temp_at_tip, parked, dev_private_key FROM handles{} ORDER BY id DESC LIMIT ? OFFSET ?",
                where_clause
            );
            params.push(limit.to_string());
            params.push(offset.to_string());
            let mut stmt = conn.prepare(&sql)?;
            let handles = stmt
                .query_map(params_from_iter(params.iter().map(|s| s as &dyn rusqlite::types::ToSql)), |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                        published_temp_at_tip: row.get(6)?,
                        parked: row.get::<_, i64>(7)? != 0,
                            dev_private_key: row.get(8)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    /// List staged handles eligible for commit (not parked)
    pub async fn list_staged_handles(&self) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status, published_temp_at_tip, parked, dev_private_key FROM handles WHERE commitment_root IS NULL AND parked = 0 ORDER BY id ASC")?;
            let handles = stmt
                .query_map([], |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                        published_temp_at_tip: row.get(6)?,
                        parked: row.get::<_, i64>(7)? != 0,
                            dev_private_key: row.get(8)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    /// Commit unparked staged handles by setting their commitment_root and commitment_idx
    pub async fn commit_staged_handles(&self, root: &str, idx: usize) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        let root = root.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count = conn.execute(
                "UPDATE handles SET commitment_root = ?, commitment_idx = ? WHERE commitment_root IS NULL AND parked = 0",
                params![root, idx as i64],
            )?;
            Ok(count)
        })
        .await?
    }

    /// Count staged handles eligible for commit (not parked)
    pub async fn staged_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM handles WHERE commitment_root IS NULL AND parked = 0",
                [],
                |row| row.get(0),
            )?;
            Ok(count as usize)
        })
        .await?
    }

    /// Count parked handles
    pub async fn parked_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM handles WHERE commitment_root IS NULL AND parked = 1",
                [],
                |row| row.get(0),
            )?;
            Ok(count as usize)
        })
        .await?
    }

    /// Count committed handles (commitment_root IS NOT NULL)
    pub async fn committed_handle_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM handles WHERE commitment_root IS NOT NULL",
                [],
                |row| row.get(0),
            )?;
            Ok(count as usize)
        })
        .await?
    }

    pub async fn get_handle_spk(&self, name: &str) -> anyhow::Result<Option<ScriptBuf>> {
        let conn = self.conn.clone();
        let name = name.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let spk = conn
                .query_row(
                    "SELECT script_pubkey FROM handles WHERE name = ?",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(spk.map(|spk| ScriptBuf::from_bytes(spk)))
        })
            .await?
    }

    /// Check if a handle is staged (exists with NULL commitment_root)
    pub async fn is_staged(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.conn.clone();
        let name = name.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let spk = conn
                .query_row(
                    "SELECT script_pubkey FROM handles WHERE name = ? AND commitment_root IS NULL",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(spk)
        })
        .await?
    }

    /// List handles by commitment root
    pub async fn list_handles_by_commitment(&self, root: &str) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        let root = root.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status, published_temp_at_tip, parked, dev_private_key FROM handles WHERE commitment_root = ? ORDER BY name ASC",
            )?;
            let handles = stmt
                .query_map(params![root], |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                        published_temp_at_tip: row.get(6)?,
                        parked: row.get::<_, i64>(7)? != 0,
                            dev_private_key: row.get(8)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    // Park / Unpark

    /// Set parked status for handles by name (only affects staged handles)
    /// Park or unpark staged handles.
    /// If `names` is non-empty, parks those specific handles.
    /// Otherwise uses `search`/`filter` to match handles in bulk.
    pub async fn set_parked(
        &self,
        names: &[String],
        parked: bool,
        search: Option<String>,
        filter: Option<String>,
    ) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        let names = names.to_vec();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let val: i64 = if parked { 1 } else { 0 };
            if !names.is_empty() {
                let mut count = 0usize;
                for name in &names {
                    count += conn.execute(
                        "UPDATE handles SET parked = ? WHERE name = ? AND commitment_root IS NULL",
                        params![val, name],
                    )?;
                }
                Ok(count)
            } else {
                let (where_clause, filter_params) = build_handle_filter(&search, &filter);
                let sql = if where_clause.is_empty() {
                    "UPDATE handles SET parked = ? WHERE commitment_root IS NULL".to_string()
                } else {
                    // Merge the filter conditions with the staged-only guard
                    format!(
                        "UPDATE handles SET parked = ?{} AND commitment_root IS NULL",
                        where_clause.replacen("WHERE", "WHERE", 1).replace("WHERE", "AND")
                    )
                };
                let mut all: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(val)];
                for p in &filter_params {
                    all.push(Box::new(p.clone()));
                }
                let refs: Vec<&dyn rusqlite::types::ToSql> = all.iter().map(|b| b.as_ref()).collect();
                let count = conn.execute(&sql, refs.as_slice())?;
                Ok(count)
            }
        })
        .await?
    }

    /// Remove staged handles (not committed)
    pub async fn remove_staged_handles(
        &self,
        names: &[String],
        search: Option<String>,
        filter: Option<String>,
    ) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        let names = names.to_vec();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            if !names.is_empty() {
                let mut count = 0usize;
                for name in &names {
                    count += conn.execute(
                        "DELETE FROM handles WHERE name = ? AND commitment_root IS NULL",
                        params![name],
                    )?;
                }
                Ok(count)
            } else {
                let (where_clause, filter_params) = build_handle_filter(&search, &filter);
                let sql = if where_clause.is_empty() {
                    "DELETE FROM handles WHERE commitment_root IS NULL".to_string()
                } else {
                    format!(
                        "DELETE FROM handles{} AND commitment_root IS NULL",
                        where_clause.replacen("WHERE", "WHERE", 1).replace("WHERE", "AND")
                    )
                };
                let mut all: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
                for p in &filter_params {
                    all.push(Box::new(p.clone()));
                }
                let refs: Vec<&dyn rusqlite::types::ToSql> = all.iter().map(|b| b.as_ref()).collect();
                let count = conn.execute(&sql, refs.as_slice())?;
                Ok(count)
            }
        })
        .await?
    }

    // Rollback

    /// Delete the last commitment and unstage its handles.
    /// Fails if the commitment has already been broadcast.
    /// Call this AFTER rolling back spacedb.
    pub async fn rollback_last_commitment(&self) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let (id, root, txid): (i64, String, Option<String>) = conn.query_row(
                "SELECT id, root, commit_txid FROM commitments ORDER BY idx DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).map_err(|_| anyhow!("no commitments to rollback"))?;

            if txid.is_some() {
                return Err(anyhow!("cannot rollback: commitment already broadcast"));
            }

            // Unstage handles: clear commitment fields but preserve publish status
            // (temp certs are still valid since nothing changed on-chain)
            conn.execute(
                "UPDATE handles SET commitment_root = NULL, commitment_idx = NULL \
                 WHERE commitment_root = ?",
                params![root],
            )?;

            // Delete the commitment row
            conn.execute("DELETE FROM commitments WHERE id = ?", params![id])?;

            Ok(())
        })
        .await?
    }

    /// Cleanup: delete an unbroadcast commitment whose root doesn't match
    /// the current spacedb root (partial rollback recovery).
    pub async fn cleanup_orphaned_commitment(&self, spacedb_root: &str) -> anyhow::Result<bool> {
        let conn = self.conn.clone();
        let spacedb_root = spacedb_root.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let last: Option<(i64, String, Option<String>)> = conn.query_row(
                "SELECT id, root, commit_txid FROM commitments ORDER BY idx DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;

            let Some((id, root, txid)) = last else { return Ok(false) };
            if txid.is_some() { return Ok(false) }
            if root == spacedb_root { return Ok(false) }

            // Orphaned: spacedb was rolled back but SQLite wasn't
            conn.execute(
                "UPDATE handles SET commitment_root = NULL, commitment_idx = NULL \
                 WHERE commitment_root = ?",
                params![root],
            )?;
            conn.execute("DELETE FROM commitments WHERE id = ?", params![id])?;

            Ok(true)
        })
        .await?
    }

    // Publishing

    /// Select handles for publishing based on the given selector.
    pub async fn select_handles(&self, selector: HandleSelector) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let cols = "id, name, script_pubkey, commitment_root, commitment_idx, publish_status, published_temp_at_tip, parked, dev_private_key";
            let map_row = |row: &rusqlite::Row| -> rusqlite::Result<Handle> {
                Ok(Handle {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    script_pubkey: row.get(2)?,
                    commitment_root: row.get(3)?,
                    commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                    publish_status: row.get(5)?,
                    published_temp_at_tip: row.get(6)?,
                    parked: row.get::<_, i64>(7)? != 0,
                            dev_private_key: row.get(8)?,
                })
            };
            match selector {
                HandleSelector::Unpublished(confirmed_idx) => {
                    let sql = format!(
                        "SELECT {} FROM handles WHERE publish_status IS NULL \
                         OR (publish_status = 'temp' AND commitment_idx IS NOT NULL AND commitment_idx <= ?) \
                         ORDER BY name ASC", cols
                    );
                    let idx_param = confirmed_idx.map(|v| v as i64).unwrap_or(-1);
                    let mut stmt = conn.prepare(&sql)?;
                    let result: Vec<Handle> = stmt.query_map(params![idx_param], map_row)?.collect::<Result<Vec<_>, _>>()?;
                    Ok(result)
                }
                HandleSelector::ByName(names) => {
                    if names.is_empty() {
                        return Ok(Vec::new());
                    }
                    let placeholders = vec!["?"; names.len()].join(",");
                    let sql = format!(
                        "SELECT {} FROM handles WHERE name IN ({}) ORDER BY name ASC",
                        cols, placeholders
                    );
                    let mut stmt = conn.prepare(&sql)?;
                    let result: Vec<Handle> = stmt.query_map(params_from_iter(names.iter()), map_row)?.collect::<Result<Vec<_>, _>>()?;
                    Ok(result)
                }
            }
        })
        .await?
    }

    /// Mark handles as published with a given status ('temp' or 'final').
    /// When status is 'temp', `tip` should be the current on-chain root hex.
    pub async fn mark_handles_published(
        &self,
        names: &[String],
        status: &str,
        tip: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let names = names.to_vec();
        let status = status.to_string();
        let tip = tip.map(|s| s.to_string());
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            for name in &names {
                conn.execute(
                    "UPDATE handles SET publish_status = ?, published_temp_at_tip = ? WHERE name = ?",
                    params![status, tip, name],
                )?;
            }
            Ok(())
        })
        .await?
    }

    /// Reset publish_status to NULL for temp-published handles whose cert
    /// was issued against a different on-chain tip (stale chain proof).
    pub async fn reset_stale_temp_certs(&self, current_tip: Option<&str>) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        let current_tip = current_tip.map(|s| s.to_string());
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count = match &current_tip {
                Some(tip) => conn.execute(
                    "UPDATE handles SET publish_status = NULL, published_temp_at_tip = NULL
                     WHERE publish_status = 'temp'
                       AND (published_temp_at_tip IS NULL OR published_temp_at_tip != ?)",
                    params![tip],
                )?,
                None => conn.execute(
                    "UPDATE handles SET publish_status = NULL, published_temp_at_tip = NULL
                     WHERE publish_status = 'temp'",
                    [],
                )?,
            };
            Ok(count)
        })
        .await?
    }

    /// Mark a commitment as published
    pub async fn mark_commitment_published(&self, commitment_id: i64) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET published_at = datetime('now') WHERE id = ?",
                params![commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    // Receipts

    pub async fn store_receipt(&self, kind: &str, data: &[u8]) -> anyhow::Result<i64> {
        let conn = self.conn.clone();
        let kind = kind.to_string();
        let data = data.to_vec();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO receipts (kind, data) VALUES (?, ?)",
                params![kind, data],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?
    }

    pub async fn get_receipt(&self, id: i64) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let data = conn
                .query_row("SELECT data FROM receipts WHERE id = ?", params![id], |row| {
                    row.get(0)
                })
                .optional()?;
            Ok(data)
        })
        .await?
    }
}

/// Build a WHERE clause and params for handle search/filter queries.
fn build_handle_filter(search: &Option<String>, filter: &Option<String>) -> (String, Vec<String>) {
    let mut conditions = Vec::new();
    let mut params = Vec::new();

    if let Some(q) = search {
        if !q.is_empty() {
            conditions.push("name LIKE ?".to_string());
            params.push(format!("%{}%", q));
        }
    }

    if let Some(f) = filter {
        match f.as_str() {
            "staged" => conditions.push("commitment_root IS NULL".to_string()),
            "committed" => conditions.push("commitment_root IS NOT NULL".to_string()),
            "parked" => conditions.push("parked = 1".to_string()),
            "published" => conditions.push("publish_status IS NOT NULL".to_string()),
            "unpublished" => conditions.push("publish_status IS NULL".to_string()),
            _ => {}
        }
    }

    if conditions.is_empty() {
        (String::new(), params)
    } else {
        (format!(" WHERE {}", conditions.join(" AND ")), params)
    }
}
