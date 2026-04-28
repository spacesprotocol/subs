//! Core business logic for subs - usable as a library.
//!
//! This module provides the core functionality without CLI dependencies.
//! All operations return structured results instead of printing.
//! Database and file I/O are run on blocking threads via `spawn_blocking`.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{fs, io};

use anyhow::anyhow;
use bitcoin::ScriptBuf;
use libveritas::cert::{Certificate, HandleOut, HandleSubtree, Signature, Witness};
use libveritas::constants::{FOLD_ID, STEP_ID};
use spaces_protocol::sname::{NameLike, SName, Subname};
use libveritas_zk::guest::Commitment as ZkCommitment;
use libveritas_zk::BatchReader;
use risc0_zkvm::Receipt;
use serde::Serialize;
use spacedb::db::Database;
use spacedb::subtree::SubTree;
use spacedb::tx::{ProofType, ReadTransaction};
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spaces_protocol::slabel::SLabel;
pub use subs_types::{CompressInput, ProvingRequest};
use tokio::task::spawn_blocking;

use crate::storage::Storage;
use crate::{Batch, BatchEntry, HandleRequest};

/// Result of adding requests to staging
#[derive(Debug, Clone, Serialize)]
pub struct AddResult {
    /// Entries added per space
    pub by_space: Vec<SpaceAddResult>,
    /// Total entries added across all spaces
    pub total_added: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceAddResult {
    pub space: SLabel,
    pub added: Vec<SName>,
    pub skipped: Vec<SkippedEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedEntry {
    pub handle: SName,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Serialize)]
pub enum SkipReason {
    AlreadyCommittedDifferentSpk,
    AlreadyStagedDifferentSpk,
    AlreadyCommitted,
    AlreadyStaged,
}

impl SkipReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            SkipReason::AlreadyCommittedDifferentSpk => "already committed with different spk",
            SkipReason::AlreadyStagedDifferentSpk => "already staged with different spk",
            SkipReason::AlreadyCommitted => "already committed",
            SkipReason::AlreadyStaged => "already staged",
        }
    }
}

/// Result of committing staged entries
#[derive(Debug, Clone, Serialize)]
pub struct CommitResult {
    pub commits: Vec<SpaceCommitResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceCommitResult {
    pub space: SLabel,
    pub prev_root: Option<String>,
    pub root: String,
    pub handles_committed: usize,
    pub is_initial: bool,
}

/// Result of proving commitments
#[derive(Debug, Clone, Serialize)]
pub struct ProveResult {
    pub spaces: Vec<SpaceProveResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceProveResult {
    pub space: SLabel,
    pub steps_proved: usize,
    pub steps_skipped: usize,
    pub aggregated: bool,
    pub step_times: Vec<StepProveInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepProveInfo {
    pub idx: usize,
    pub prev_root: Option<String>,
    pub root: String,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Result of compressing proofs to SNARK
#[derive(Debug, Clone, Serialize)]
pub struct CompressResult {
    pub spaces: Vec<SpaceCompressResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceCompressResult {
    pub space: SLabel,
    pub compressed: bool,
    pub skipped_reason: Option<String>,
}

/// Warning about an untracked on-chain commitment.
#[derive(Debug, Clone, Serialize)]
pub struct HealthWarning {
    pub message: String,
    pub chain_root: String,
    pub block_height: u32,
    pub commit_txid: Option<String>,
    /// True if the commitment can still be rolled back (not yet finalized).
    pub can_rollback: bool,
    /// Blocks remaining until the commitment is finalized (0 if already finalized).
    pub blocks_until_finalized: u32,
}

/// Status of a space
#[derive(Debug, Clone, Serialize)]
pub struct SpaceStatus {
    pub space: SLabel,
    pub commitments: usize,
    pub total_handles: usize,
    pub staged_handles: usize,
    pub committed_handles: usize,
    pub parked_handles: usize,
    pub pending_proofs: usize,
    pub has_receipt: bool,
    pub has_groth16: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_warning: Option<HealthWarning>,
}

/// Result of status query
#[derive(Debug, Clone, Serialize, Default)]
pub struct StatusResult {
    pub spaces: Vec<SpaceStatus>,
}

/// Local proof data for building a space/root certificate
///
/// The caller must fetch on-chain proofs (spaces proof, ptrs proof) via RPC
/// and combine with this data to build the final Certificate.
pub struct SpaceReceipt {
    /// The ZK receipt proving the commitment chain (None for initial single-entry)
    pub receipt: Option<Receipt>,
    /// The commitment/state root (None if no entries committed yet)
    pub commitment_root: Option<[u8; 32]>,
}

/// Local proof data for building a handle/leaf certificate
///
/// The caller must fetch the key rotation proof via RPC
/// and combine with this data to build the final Certificate.
pub struct LocalHandleProof {
    /// The subject handle
    pub subject: SName,
    /// The genesis script pubkey for this handle
    pub script_pubkey: Vec<u8>,
    /// Merkle inclusion proof from SpaceDB
    pub inclusion_proof: SubTree<Sha256Hasher>,
}

/// A local space with cached database connections.
///
/// Holds the storage (SQLite) and SpaceDB connections for a single space.
/// Database and file operations are offloaded to blocking threads.
pub struct LocalSpace {
    name: SLabel,
    storage: Storage,
    db: Arc<Mutex<Database<Sha256Hasher>>>,
}

impl LocalSpace {
    pub async fn new(name: SLabel, dir: PathBuf) -> anyhow::Result<Self> {
        let dir_clone = dir.clone();
        spawn_blocking(move || fs::create_dir_all(&dir_clone)).await??;

        let storage = Storage::open(&dir.join("subs.db")).await?;
        if storage.get_space().await?.is_none() {
            storage.set_space(&name).await?;
        }

        let db_path = dir.join(format!("{}.sdb", name));
        let db = spawn_blocking(move || Database::open(db_path.to_str().unwrap())).await??;

        Ok(Self {
            name,
            storage,
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub fn name(&self) -> &SLabel {
        &self.name
    }

    pub fn storage(&self) -> Storage {
        self.storage.clone()
    }

    pub fn db(&self) -> Arc<Mutex<Database<Sha256Hasher>>> {
        self.db.clone()
    }

    fn get_handle_proof_sync(
        db: &Database<Sha256Hasher>,
        handle: &SName,
        tip: [u8;32]
    ) -> anyhow::Result<LocalHandleProof> {
       let mut snap = get_snapshot_for_tip(db, tip)?;
        let subspace = handle
            .subspace()
            .ok_or_else(|| anyhow!("handle must have subspace"))?;
        let key = Sha256Hasher::hash(subspace.as_slabel().as_ref());
        let value = snap
            .get(&key)?
            .ok_or_else(|| anyhow!("handle '{}' not found", handle))?;
        let handle_out = HandleOut::from_slice(&value)
            .map_err(|e| anyhow!("invalid handle tree entry for '{}': {}", handle, e))?;

        let inclusion_proof = snap
            .prove(&[key], ProofType::Standard)
            .map_err(|e| anyhow!("could not generate inclusion proof: {}", e))?;

        Ok(LocalHandleProof {
            subject: handle.clone(),
            script_pubkey: handle_out.spk.into_bytes(),
            inclusion_proof,
        })
    }

    /// Get status of this space
    pub async fn status(&self) -> anyhow::Result<SpaceStatus> {
        let staged = self.storage.staged_count().await?;
        let committed = self.storage.committed_handle_count().await?;
        let parked = self.storage.parked_count().await?;
        let commitments = self.storage.list_commitments().await?;
        let pending_proofs = count_pending_proofs(&commitments);
        Ok(SpaceStatus {
            space: self.name.clone(),
            commitments: commitments.len(),
            total_handles: staged + committed + parked,
            staged_handles: staged,
            committed_handles: committed,
            parked_handles: parked,
            pending_proofs,
            has_receipt: self.storage.get_tip_receipt_id().await?.is_some(),
            has_groth16: self.storage.get_tip_groth16_id().await?.is_some(),
            health_warning: None,
        })
    }

    /// Stage a single handle request
    pub async fn add_request(
        &self,
        request: &HandleRequest,
    ) -> anyhow::Result<Option<SkippedEntry>> {
        let script_pubkey = hex::decode(&request.script_pubkey)
            .map_err(|e| anyhow!("Invalid script_pubkey hex: {}", e))?;

        let sub_label = request.handle.subspace().expect("subspace").clone();
        let sub_label_key = sub_label.as_slabel().as_ref().to_vec();
        let handle_name = sub_label.to_string();

        // Check if already committed in SpaceDB
        let db = self.db.clone();
        let spk_clone = script_pubkey.clone();
        let handle_clone = request.handle.clone();
        let db_result: Option<SkippedEntry> = spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut reader = db.begin_read()?;
            if let Some(existing_bytes) = reader.get(&Sha256Hasher::hash(&sub_label_key))? {
                let reason = if HandleOut::from_slice(&existing_bytes)
                    .map(|h| h.spk.as_bytes() != spk_clone.as_slice())
                    .unwrap_or(true)
                {
                    SkipReason::AlreadyCommittedDifferentSpk
                } else {
                    SkipReason::AlreadyCommitted
                };
                return Ok(Some(SkippedEntry {
                    handle: handle_clone,
                    reason,
                }));
            }
            Ok::<_, anyhow::Error>(None)
        })
        .await??;

        if db_result.is_some() {
            return Ok(db_result);
        }

        // Check if already staged
        if let Some(existing) = self.storage.is_staged(&handle_name).await? {
            let reason = if existing != script_pubkey {
                SkipReason::AlreadyStagedDifferentSpk
            } else {
                SkipReason::AlreadyStaged
            };
            return Ok(Some(SkippedEntry {
                handle: request.handle.clone(),
                reason,
            }));
        }

        self.storage
            .add_handle(&handle_name, &script_pubkey, request.dev_private_key.as_deref())
            .await?;
        Ok(None)
    }

    /// Prepare ZK input for this space
    pub async fn prepare_zk_input(&self) -> anyhow::Result<(Option<Vec<u8>>, Batch)> {
        let staged_handles = self.storage.list_staged_handles().await?;
        if staged_handles.is_empty() {
            return Err(anyhow!("No uncommitted changes found"));
        }

        let mut batch = Batch::new(self.name.clone());
        for handle in staged_handles {
            let sub_label = Subname::from_str(&handle.name)
                .map_err(|e| anyhow!("invalid handle name '{}': {}", handle.name, e))?;
            batch.entries.push(BatchEntry {
                sub_label,
                script_pubkey: handle.script_pubkey.into(),
            });
        }

        if self.storage.commitment_count().await? == 0 {
            return Ok((None, batch));
        }

        // Generate exclusion proof from SpaceDB
        let db = self.db.clone();
        let zk_batch = batch.to_zk_input();
        let exclusion_proof = spawn_blocking(move || {
            let reader = BatchReader(zk_batch.as_slice());
            let keys = reader
                .iter()
                .map(|t| {
                    t.handle.try_into().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid subspace hash")
                    })
                })
                .collect::<Result<Vec<Hash>, io::Error>>()?;
            let db = db.lock().unwrap();
            let mut snapshot = db.begin_read()?;
            let proof = snapshot.prove(&keys, ProofType::Standard).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("could not generate exclusion proof: {}", e),
                )
            })?;
            let encoded = borsh::to_vec(&proof).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("could not encode exclusion proof: {}", e),
                )
            })?;
            Ok::<_, anyhow::Error>(encoded)
        })
        .await??;

        Ok((Some(exclusion_proof), batch))
    }

    /// Commit staged handles for this space
    pub async fn commit(&self, dry_run: bool) -> anyhow::Result<SpaceCommitResult> {
        if self.storage.staged_count().await? == 0 {
            return Err(anyhow!("No changes to commit for space {}", self.name));
        }

        let (exclusion_proof_opt, batch) = self.prepare_zk_input().await?;
        let zk_batch = batch.to_zk_input();
        let handles_committed = batch.entries.len();
        let name = self.name.clone();

        match exclusion_proof_opt {
            Some(exclusion_proof) => {
                let c = libveritas_zk::guest::run(
                    exclusion_proof.clone(),
                    zk_batch.clone(),
                    STEP_ID,
                    FOLD_ID,
                )
                .map_err(|e| anyhow!("could not validate program input: {}", e))?;

                if dry_run {
                    return Ok(SpaceCommitResult {
                        space: name,
                        prev_root: Some(hex::encode(&c.initial_root)),
                        root: hex::encode(&c.final_root),
                        handles_committed,
                        is_initial: false,
                    });
                }

                let prev_hex = hex::encode(&c.initial_root);
                let root_hex = hex::encode(&c.final_root);

                let (_, idx) = self.storage
                    .add_commitment(
                        Some(&prev_hex),
                        &root_hex,
                        &zk_batch,
                        Some(&exclusion_proof),
                    )
                    .await?;

                let db = self.db.clone();
                let entries = batch.entries;
                spawn_blocking(move || {
                    let db = db.lock().unwrap();
                    let mut tx = db.begin_write()?;
                    for e in entries {
                        let handle_out = HandleOut {
                            name: e.sub_label.as_slabel().clone(),
                            spk: e.script_pubkey.clone(),
                        };
                        tx = tx.insert(
                            Sha256Hasher::hash(e.sub_label.as_slabel().as_ref()),
                            handle_out.to_vec(),
                        )?;
                    }
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(())
                })
                .await??;

                self.storage.commit_staged_handles(&root_hex, idx).await?;

                Ok(SpaceCommitResult {
                    space: name,
                    prev_root: Some(prev_hex),
                    root: root_hex,
                    handles_committed,
                    is_initial: false,
                })
            }

            None => {
                if dry_run {
                    return Ok(SpaceCommitResult {
                        space: name,
                        prev_root: None,
                        root: String::new(),
                        handles_committed,
                        is_initial: true,
                    });
                }

                let db = self.db.clone();
                let entries = batch.entries;
                let end_root = spawn_blocking(move || {
                    let db = db.lock().unwrap();
                    let mut tx = db.begin_write()?;
                    for e in &entries {
                        let handle_out = HandleOut {
                            name: e.sub_label.as_slabel().clone(),
                            spk: e.script_pubkey.clone(),
                        };
                        tx = tx.insert(
                            Sha256Hasher::hash(e.sub_label.as_slabel().as_ref()),
                            handle_out.to_vec(),
                        )?;
                    }
                    tx.commit()?;
                    let root = db.begin_read().expect("read").compute_root().expect("root");
                    Ok::<_, anyhow::Error>(hex::encode(root))
                })
                .await??;

                let (_, idx) = self.storage
                    .add_commitment(None, &end_root, &zk_batch, None)
                    .await?;
                self.storage.commit_staged_handles(&end_root, idx).await?;

                Ok(SpaceCommitResult {
                    space: name,
                    prev_root: None,
                    root: end_root,
                    handles_committed,
                    is_initial: true,
                })
            }
        }
    }

    /// Rollback the last local commitment.
    ///
    /// Rolls back spacedb first (source of truth), then cleans up SQLite.
    /// Safe against crashes: startup consistency check will finish cleanup
    /// if we crash between spacedb rollback and SQLite cleanup.
    pub async fn rollback_local(&self) -> anyhow::Result<()> {
        let last = self.storage.get_last_commitment().await?
            .ok_or_else(|| anyhow!("no commitments to rollback"))?;
        if last.commit_txid.is_some() {
            return Err(anyhow!("cannot rollback: commitment already broadcast"));
        }

        let mut root_bytes = [0u8; 32];
        hex::decode_to_slice(&last.root, &mut root_bytes)
            .map_err(|e| anyhow!("invalid root: {}", e))?;

        // Step 1: Rollback spacedb (source of truth)
        let db = self.db.clone();
        spawn_blocking(move || {
            let db = db.lock().unwrap();
            rollback_local_commitment(&db, root_bytes)
        })
        .await??;

        // Step 2: Clean up SQLite
        self.storage.rollback_last_commitment().await?;

        log::info!("[{}] Rolled back last commitment (idx {})", self.name, last.idx);
        Ok(())
    }

    /// Check consistency between spacedb and SQLite on startup.
    /// If spacedb was rolled back but SQLite wasn't (crash during rollback),
    /// finishes the SQLite cleanup.
    pub async fn check_consistency(&self) -> anyhow::Result<()> {
        let db = self.db.clone();
        let spacedb_root = spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut snap = db.begin_read()?;
            let root = snap.compute_root()?;
            Ok::<_, anyhow::Error>(hex::encode(root))
        })
        .await??;

        if self.storage.cleanup_orphaned_commitment(&spacedb_root).await? {
            log::warn!("[{}] Cleaned up orphaned commitment (partial rollback recovery)", self.name);
        }
        Ok(())
    }

    /// Look up a handle in SpaceDB
    pub async fn lookup_handle_in_tree(&self, sub_label: &Subname, tip: Option<[u8;32]>) -> anyhow::Result<Option<Vec<u8>>> {
        let tip = match tip {
            None => return Ok(None),
            Some(t) => t,
        };
        let db = self.db.clone();
        let sub_label = sub_label.clone();
        spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut snap = get_snapshot_for_tip(&db, tip)?;
            let key = Sha256Hasher::hash(sub_label.as_slabel().as_ref());
            Ok(snap.get(&key)?)
        })
        .await?
    }

    /// Get the current tree root
    pub async fn get_tree_root(&self) -> anyhow::Result<[u8; 32]> {
        let db = self.db.clone();
        spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut snap = db.begin_read()?;
            Ok(snap.compute_root()?)
        })
        .await?
    }

    /// Get staged script pubkey for a handle
    pub async fn get_staged(&self, sub_label: &Subname) -> anyhow::Result<Option<Vec<u8>>> {
        let handle_name = sub_label.to_string();
        self.storage.is_staged(&handle_name).await
    }

    pub async fn get_handle_spk(&self, sub_label: &Subname) -> anyhow::Result<Option<ScriptBuf>> {
        let handle_name = sub_label.to_string();
        self.storage.get_handle_spk(&handle_name).await
    }

    /// Load a receipt and extract commitment info
    pub async fn load_receipt_and_commitment(
        &self,
        receipt_id: i64,
    ) -> anyhow::Result<(Receipt, ZkCommitment)> {
        let receipt_data = self
            .storage
            .get_receipt(receipt_id)
            .await?
            .ok_or_else(|| anyhow!("Receipt {} not found", receipt_id))?;
        let receipt: Receipt = borsh::from_slice(&receipt_data)
            .map_err(|e| anyhow!("could not decode receipt: {}", e))?;
        let zk_commitment: ZkCommitment = receipt.journal.decode()?;
        Ok((receipt, zk_commitment))
    }

    /// Get the tip receipt.
    ///
    /// If `prefer_compressed` is true, returns groth16 receipt if available.
    pub async fn get_tip_receipt(
        &self,
        prefer_compressed: bool,
    ) -> anyhow::Result<Option<(Receipt, ZkCommitment)>> {
        let receipt_id = if prefer_compressed {
            self.storage.get_tip_groth16_id().await?
        } else {
            self.storage.get_tip_receipt_id().await?
        };

        match receipt_id {
            Some(id) => {
                let (receipt, commitment) = self.load_receipt_and_commitment(id).await?;
                Ok(Some((receipt, commitment)))
            }
            None => Ok(None),
        }
    }

    /// Get local proof data for building a space/root certificate.
    ///
    /// If `prefer_compressed` is true, returns groth16 receipt if available.
    pub async fn get_receipt(
        &self,
        tip: Option<[u8; 32]>,
        prefer_compressed: bool,
    ) -> anyhow::Result<SpaceReceipt> {
        let tip = match tip {
            None => {
                return Ok(SpaceReceipt {
                    receipt: None,
                    commitment_root: None,
                })
            }
            Some(t) => t,
        };

        let tip_hex = hex::encode(tip);
        let commitment = self.storage.get_commitment_by_root(&tip_hex).await?
            .ok_or_else(|| anyhow!("No commitment found for tip {}", tip_hex))?;

        if commitment.idx == 0 {
            return Ok(SpaceReceipt {
                receipt: None,
                commitment_root: Some(tip),
            });
        }

        // idx 1: only has a step receipt (no fold needed)
        // idx 2+: must use the aggregate (folded) receipt, never fall back to step
        let receipt_id = if commitment.idx <= 1 {
            if prefer_compressed {
                commitment.aggregate_groth16_id
                    .or(commitment.step_receipt_id)
            } else {
                commitment.step_receipt_id
            }
        } else if prefer_compressed {
            commitment.aggregate_groth16_id
                .or(commitment.aggregate_receipt_id)
        } else {
            commitment.aggregate_receipt_id
        };

        let receipt_id = receipt_id
            .ok_or_else(|| anyhow!("No receipt for commitment #{}", commitment.idx))?;

        let (receipt, _) = self.load_receipt_and_commitment(receipt_id).await?;

        Ok(SpaceReceipt {
            receipt: Some(receipt),
            commitment_root: Some(tip),
        })
    }

    /// Get local proof data for building a handle/leaf certificate
    pub async fn get_handle_proof(&self, handle: &SName, tip: [u8;32]) -> anyhow::Result<LocalHandleProof> {
        let db = self.db.clone();
        let handle = handle.clone();
        spawn_blocking(move || {
            let db = db.lock().unwrap();
            Self::get_handle_proof_sync(&db, &handle, tip)
        })
        .await?
    }

    /// Issue a certificate for a subject.
    pub async fn issue_cert(
        &self,
        subject: &SName,
        tip: [u8; 32],
    ) -> anyhow::Result<Certificate> {
        if subject.is_single_label() {
            return Ok(Certificate::new(
                subject.clone(),
                Witness::Root {
                    receipt: self.get_receipt(Some(tip), true).await?.receipt,
                },
            ));
        }
        let proof = self.get_handle_proof(subject, tip).await?;
        Ok(Certificate::new(
            subject.clone(),
            Witness::Leaf {
                genesis_spk: ScriptBuf::from_bytes(proof.script_pubkey),
                handles: HandleSubtree(proof.inclusion_proof),
                signature: None,
            },
        ))
    }

    /// Issue a temporary certificate for a staged (uncommitted) handle.
    ///
    /// Temporary certificates are used for handles that haven't been committed yet.
    /// They include an optional exclusion proof (if prior commits exist) and signature.
    pub async fn issue_temp_cert(
        &self,
        handle: &SName,
        tip: Option<[u8; 32]>,
        signature: [u8; 64],
    ) -> anyhow::Result<Certificate> {
        let subspace = handle
            .subspace()
            .ok_or_else(|| anyhow!("handle must have subspace"))?;
        let handle_name = subspace.to_string();

        let script_pubkey = self
            .storage
            .get_handle_spk(&handle_name)
            .await?
            .ok_or_else(|| anyhow!("handle '{}' is not staged", handle))?;

        let exclusion = if let Some(tip) = tip {
            let db = self.db.clone();
            let subspace = subspace.clone();
            spawn_blocking(move || {
                let db = db.lock().unwrap();
                let mut snap = get_snapshot_for_tip(&db, tip)?;
                let key = Sha256Hasher::hash(subspace.as_slabel().as_ref());
                let exclusion_proof = snap
                    .prove(&[key], ProofType::Standard)
                    .map_err(|e| anyhow!("could not generate exclusion proof: {}", e))?;
                Ok::<_, anyhow::Error>(HandleSubtree(exclusion_proof))
            })
            .await??
        } else {
            HandleSubtree(SubTree::empty())
        };

        Ok(Certificate::new(
            handle.clone(),
            Witness::Leaf {
                genesis_spk: script_pubkey,
                handles: exclusion,
                signature: Some(Signature(signature)),
            },
        ))
    }

    /// Get the next proving request for this space.
    /// Returns None when all proofs are complete.
    pub async fn get_next_proving_request(&self) -> anyhow::Result<Option<ProvingRequest>> {
        let commitments = self.storage.list_commitments().await?;

        if commitments.len() < 2 {
            return Ok(None);
        }

        // First, check for any pending step proofs
        for commitment in commitments.iter().skip(1) {
            if commitment.step_receipt_id.is_some() {
                continue;
            }

            let exclusion_proof = commitment
                .exclusion_merkle_proof
                .as_ref()
                .ok_or_else(|| anyhow!("[#{}] missing exclusion_merkle_proof", commitment.idx))?;

            return Ok(Some(ProvingRequest::Step {
                commitment_id: commitment.id,
                idx: commitment.idx,
                prev_root: commitment.prev_root.clone(),
                root: commitment.root.clone(),
                exclusion_proof: exclusion_proof.clone(),
                zk_batch: commitment.zk_batch.clone(),
            }));
        }

        // All steps done, check for pending folds
        let mut acc_receipt: Option<Vec<u8>> = None;
        let mut acc_commit: Option<ZkCommitment> = None;

        for commitment in commitments.iter().skip(1) {
            let step_receipt_id = match commitment.step_receipt_id {
                Some(id) => id,
                None => continue,
            };

            let step_receipt_bytes = self
                .storage
                .get_receipt(step_receipt_id)
                .await?
                .ok_or_else(|| anyhow!("step receipt {} not found", step_receipt_id))?;
            let step_receipt: Receipt = borsh::from_slice(&step_receipt_bytes)?;
            let step_commit: ZkCommitment = step_receipt.journal.decode()?;

            if acc_receipt.is_none() {
                acc_receipt = Some(step_receipt_bytes);
                acc_commit = Some(step_commit);
                continue;
            }

            if let Some(agg_id) = commitment.aggregate_receipt_id {
                let agg_receipt_bytes = self
                    .storage
                    .get_receipt(agg_id)
                    .await?
                    .ok_or_else(|| anyhow!("aggregate receipt {} not found", agg_id))?;
                let agg_receipt: Receipt = borsh::from_slice(&agg_receipt_bytes)?;
                let agg_commit: ZkCommitment = agg_receipt.journal.decode()?;
                acc_receipt = Some(agg_receipt_bytes);
                acc_commit = Some(agg_commit);
                continue;
            }

            return Ok(Some(ProvingRequest::Fold {
                commitment_id: commitment.id,
                idx: commitment.idx,
                prev_root: commitment.prev_root.clone(),
                root: commitment.root.clone(),
                acc_receipt: acc_receipt.clone().unwrap(),
                acc_commitment: acc_commit.clone().unwrap(),
                step_receipt: step_receipt_bytes,
                step_commitment: step_commit,
            }));
        }

        Ok(None)
    }

    /// Get input for SNARK compression. Returns None if nothing to compress.
    pub async fn get_compress_input(&self) -> anyhow::Result<Option<CompressInput>> {
        let tip_id = match self.storage.get_tip_receipt_id().await? {
            Some(id) => id,
            None => return Ok(None),
        };

        if self.storage.get_tip_groth16_id().await?.is_some() {
            return Ok(None);
        }

        let receipt_bytes = self
            .storage
            .get_receipt(tip_id)
            .await?
            .ok_or_else(|| anyhow!("tip receipt {} not found", tip_id))?;
        let receipt: Receipt = borsh::from_slice(&receipt_bytes)?;
        let zk_commitment: ZkCommitment = receipt.journal.decode()?;

        Ok(Some(CompressInput {
            receipt: receipt_bytes,
            commitment: zk_commitment,
        }))
    }

    /// Save a step receipt from an external prover
    pub async fn save_step_receipt(
        &self,
        commitment_id: i64,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let receipt_bytes = receipt_bytes.to_vec();
        let bytes_for_verify = receipt_bytes.clone();
        spawn_blocking(move || {
            let receipt: Receipt = borsh::from_slice(&bytes_for_verify)
                .map_err(|e| anyhow!("could not deserialize receipt: {}", e))?;
            receipt
                .verify(STEP_ID)
                .map_err(|e| anyhow!("step receipt verification failed: {}", e))?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let receipt_id = self.storage.store_receipt("step", &receipt_bytes).await?;
        self.storage
            .update_commitment_step_receipt(commitment_id, receipt_id)
            .await?;
        Ok(())
    }

    /// Save a fold receipt
    pub async fn save_fold_receipt(
        &self,
        commitment_id: i64,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let receipt_bytes = receipt_bytes.to_vec();
        let bytes_for_verify = receipt_bytes.clone();
        spawn_blocking(move || {
            let receipt: Receipt = borsh::from_slice(&bytes_for_verify)
                .map_err(|e| anyhow!("could not deserialize receipt: {}", e))?;
            receipt
                .verify(FOLD_ID)
                .map_err(|e| anyhow!("fold receipt verification failed: {}", e))?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let receipt_id = self.storage.store_receipt("fold", &receipt_bytes).await?;
        self.storage
            .update_commitment_aggregate_receipt(commitment_id, receipt_id)
            .await?;
        self.storage.set_tip_receipt_id(Some(receipt_id)).await?;
        Ok(())
    }

    /// Save a groth16 receipt
    pub async fn save_groth16_receipt(&self, receipt_bytes: &[u8]) -> anyhow::Result<()> {
        let receipt_bytes = receipt_bytes.to_vec();
        let bytes_for_verify = receipt_bytes.clone();
        spawn_blocking(move || {
            let receipt: Receipt = borsh::from_slice(&bytes_for_verify)
                .map_err(|e| anyhow!("could not deserialize receipt: {}", e))?;
            receipt
                .verify(FOLD_ID)
                .map_err(|e| anyhow!("groth16 receipt verification failed: {}", e))?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let groth16_id = self
            .storage
            .store_receipt("groth16", &receipt_bytes)
            .await?;
        if let Some(commitment) = self.storage.get_last_commitment().await? {
            self.storage
                .update_commitment_groth16(commitment.id, groth16_id)
                .await?;
        }
        self.storage.set_tip_groth16_id(Some(groth16_id)).await?;
        Ok(())
    }

    /// Save a receipt for a proving request (step or fold)
    pub async fn save_proving_receipt(
        &self,
        request: &ProvingRequest,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        match request {
            ProvingRequest::Step { commitment_id, .. } => {
                self.save_step_receipt(*commitment_id, receipt_bytes).await
            }
            ProvingRequest::Fold { commitment_id, .. } => {
                self.save_fold_receipt(*commitment_id, receipt_bytes).await
            }
        }
    }

    /// Save a proving receipt by commitment ID and type (for binary fulfill endpoint)
    pub async fn save_proving_receipt_by_id(
        &self,
        commitment_id: i64,
        is_fold: bool,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        if is_fold {
            self.save_fold_receipt(commitment_id, receipt_bytes).await
        } else {
            self.save_step_receipt(commitment_id, receipt_bytes).await
        }
    }

    /// Save a proving estimate for a commitment (JSON-serialized EstimateResult).
    pub async fn save_estimate(
        &self,
        commitment_id: i64,
        estimate_json: &str,
    ) -> anyhow::Result<()> {
        self.storage.update_commitment_estimate(commitment_id, estimate_json).await
    }
}

/// Count pending proofs across commitments.
///
/// - idx 0: no proof needed (genesis)
/// - idx 1: step only (1 proof)
/// - idx 2+: step + fold (2 proofs each)
pub fn count_pending_proofs(commitments: &[crate::storage::Commitment]) -> usize {
    let mut count = 0;
    for c in commitments.iter().skip(1) {
        if c.step_receipt_id.is_none() {
            count += 1;
        }
        if c.idx >= 2 && c.aggregate_receipt_id.is_none() {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;
    use std::str::FromStr;
    use tempfile::TempDir;

    fn test_space() -> SLabel {
        SLabel::try_from("@example").unwrap()
    }

    fn test_label(name: &str) -> Subname {
        Subname::from_str(name).unwrap()
    }

    fn test_script_pubkey() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x01; 25])
    }

    fn make_request(handle: &str, spk: &[u8]) -> HandleRequest {
        HandleRequest {
            handle: SName::try_from(handle).unwrap(),
            script_pubkey: hex::encode(spk),
            dev_private_key: None,
        }
    }

    #[test]
    fn test_batch_to_zk_input_format() {
        let space = test_space();
        let mut batch = Batch::new(space.clone());

        let label = test_label("alice");
        let spk = test_script_pubkey();
        batch.entries.push(BatchEntry {
            sub_label: label.clone(),
            script_pubkey: spk.clone(),
        });

        let zk_input = batch.to_zk_input();
        
        // Next 32 bytes should be sha256(subspace label)
        let subspace_hash = Sha256Hasher::hash(label.as_slabel().as_ref());
        assert_eq!(&zk_input[32..64], &subspace_hash);

        // Next 32 bytes should be sha256(script_pubkey)
        let spk_hash = Sha256Hasher::hash(spk.as_bytes());
        assert_eq!(&zk_input[64..96], &spk_hash);

        // Total size: 32 (space) + 32 (subspace) + 32 (spk) = 96 bytes
        assert_eq!(zk_input.len(), 96);
    }

    #[test]
    fn test_batch_reader_roundtrip() {
        let space = test_space();
        let mut batch = Batch::new(space.clone());

        let label = test_label("bob");
        let spk = test_script_pubkey();
        batch.entries.push(BatchEntry {
            sub_label: label.clone(),
            script_pubkey: spk.clone(),
        });

        let zk_input = batch.to_zk_input();
        let reader = BatchReader(zk_input.as_slice());

        let entries: Vec<_> = reader.iter().collect();
        assert_eq!(entries.len(), 1);

        let expected_hash = Sha256Hasher::hash(label.as_slabel().as_ref());
        assert_eq!(entries[0].handle, expected_hash);

        let handle_out = HandleOut {
            name: label.as_slabel().clone(),
            spk: spk.clone(),
        };
        let expected_value_hash = Sha256Hasher::hash(&handle_out.to_vec());
        assert_eq!(entries[0].value_hash, expected_value_hash);
    }

    #[tokio::test]
    async fn test_storage_handles_operations() {
        let storage = Storage::in_memory().await.unwrap();
        let space = test_space();
        storage.set_space(&space).await.unwrap();

        // Initially no staged handles
        assert_eq!(storage.staged_count().await.unwrap(), 0);

        // Add a handle (staged by default - commitment_root is NULL)
        let handle_name = "alice@testspace";
        let spk = test_script_pubkey();
        storage
            .add_handle(handle_name, spk.as_bytes(), None)
            .await
            .unwrap();

        assert_eq!(storage.staged_count().await.unwrap(), 1);

        // List staged handles
        let staged = storage.list_staged_handles().await.unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].name, handle_name);
        assert_eq!(staged[0].script_pubkey, spk.as_bytes());
        assert!(staged[0].commitment_root.is_none());

        // Check is_staged
        let is_staged = storage.is_staged(handle_name).await.unwrap();
        assert!(is_staged.is_some());
        assert_eq!(is_staged.unwrap(), spk.as_bytes());

        // Commit staged handles
        let committed_count = storage.commit_staged_handles("abc123", 0).await.unwrap();
        assert_eq!(committed_count, 1);
        assert_eq!(storage.staged_count().await.unwrap(), 0);

        // Handle should no longer be staged
        assert!(storage.is_staged(handle_name).await.unwrap().is_none());

        // But should still exist with commitment_root set
        let handle = storage.get_handle(handle_name).await.unwrap().unwrap();
        assert_eq!(handle.commitment_root, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_storage_commitment_operations() {
        let storage = Storage::in_memory().await.unwrap();

        assert_eq!(storage.commitment_count().await.unwrap(), 0);

        let zk_batch = vec![1, 2, 3, 4];
        storage
            .add_commitment(None, "abc123", &zk_batch, None)
            .await
            .unwrap();

        assert_eq!(storage.commitment_count().await.unwrap(), 1);
        let commitment = storage.get_commitment(0).await.unwrap().unwrap();
        assert_eq!(commitment.idx, 0);
        assert_eq!(commitment.prev_root, None);
        assert_eq!(commitment.root, "abc123");
        assert_eq!(commitment.zk_batch, zk_batch);

        storage
            .add_commitment(Some("abc123"), "def456", &vec![5, 6, 7], Some(&vec![8, 9]))
            .await
            .unwrap();
        assert_eq!(storage.commitment_count().await.unwrap(), 2);

        let commitment = storage.get_commitment(1).await.unwrap().unwrap();
        assert_eq!(commitment.idx, 1);
        assert_eq!(commitment.prev_root, Some("abc123".to_string()));
        assert_eq!(commitment.root, "def456");

        let last = storage.get_last_commitment().await.unwrap().unwrap();
        assert_eq!(last.idx, 1);
    }

    async fn create_local_space(temp_dir: &TempDir) -> LocalSpace {
        let space = test_space();
        let space_dir = temp_dir.path().join(space.to_string());
        LocalSpace::new(space, space_dir).await.unwrap()
    }

    #[tokio::test]
    async fn test_add_and_commit_initial() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        let req = make_request("alice@example", &[0x01; 25]);
        let skipped = local_space.add_request(&req).await.unwrap();
        assert!(skipped.is_none());

        let commit_result = local_space.commit(false).await.unwrap();
        assert!(commit_result.is_initial);
        assert_eq!(commit_result.handles_committed, 1);

        // Verify in SpaceDB
        let label = test_label("alice");
        let tip = local_space.get_tree_root().await.unwrap();
        let stored = local_space.lookup_handle_in_tree(&label, Some(tip)).await.unwrap();
        assert!(stored.is_some());
        let handle_out = HandleOut::from_slice(&stored.unwrap()).unwrap();
        assert_eq!(handle_out.spk.as_bytes(), &[0x01; 25]);
    }

    #[tokio::test]
    async fn test_add_and_commit_subsequent() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        // First commit
        let req1 = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req1).await.unwrap();
        let result1 = local_space.commit(false).await.unwrap();
        assert!(result1.is_initial);

        // Second commit
        let req2 = make_request("bob@example", &[0x02; 25]);
        local_space.add_request(&req2).await.unwrap();
        let result2 = local_space.commit(false).await.unwrap();
        assert!(!result2.is_initial);
        assert!(result2.prev_root.is_some());

        // Both should exist
        assert!(local_space
            .lookup_handle_in_tree(&test_label("alice"), Some(local_space.get_tree_root().await.unwrap()))
            .await
            .unwrap()
            .is_some());
        assert!(local_space
            .lookup_handle_in_tree(&test_label("bob"), Some(local_space.get_tree_root().await.unwrap()))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_skip_duplicate_in_staging() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        let req = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req).await.unwrap();

        // Adding same request again should skip
        let skipped = local_space.add_request(&req).await.unwrap();
        assert!(skipped.is_some());
        assert!(matches!(skipped.unwrap().reason, SkipReason::AlreadyStaged));
    }

    #[tokio::test]
    async fn test_skip_duplicate_after_commit() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        let req = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req).await.unwrap();
        local_space.commit(false).await.unwrap();

        // Adding same request after commit should skip
        let skipped = local_space.add_request(&req).await.unwrap();
        assert!(skipped.is_some());
        assert!(matches!(
            skipped.unwrap().reason,
            SkipReason::AlreadyCommitted
        ));
    }

    #[tokio::test]
    async fn test_reject_duplicate_with_different_spk() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        let req1 = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req1).await.unwrap();
        local_space.commit(false).await.unwrap();

        // Adding same handle with different spk should be skipped with reason
        let req2 = make_request("alice@example", &[0x02; 25]);
        let skipped = local_space.add_request(&req2).await.unwrap();
        assert!(skipped.is_some());
        assert!(matches!(
            skipped.unwrap().reason,
            SkipReason::AlreadyCommittedDifferentSpk
        ));
    }

    #[tokio::test]
    async fn test_multi_space_isolation() {
        let temp_dir = TempDir::new().unwrap();

        let space1 = SLabel::try_from("@space1").unwrap();
        let space2 = SLabel::try_from("@space2").unwrap();

        let local_space1 = LocalSpace::new(space1.clone(), temp_dir.path().join("@space1"))
            .await
            .unwrap();
        let local_space2 = LocalSpace::new(space2.clone(), temp_dir.path().join("@space2"))
            .await
            .unwrap();

        let req1 = make_request("alice@space1", &[0x01; 25]);
        let req2 = make_request("bob@space2", &[0x02; 25]);

        local_space1.add_request(&req1).await.unwrap();
        local_space2.add_request(&req2).await.unwrap();

        local_space1.commit(false).await.unwrap();
        local_space2.commit(false).await.unwrap();

        // alice only in space1
        let tip1 = Some(local_space1.get_tree_root().await.unwrap());
        let tip2 = Some(local_space2.get_tree_root().await.unwrap());
        assert!(local_space1
            .lookup_handle_in_tree(&test_label("alice"), tip1)
            .await
            .unwrap()
            .is_some());
        assert!(local_space2
            .lookup_handle_in_tree(&test_label("alice"), tip2)
            .await
            .unwrap()
            .is_none());

        // bob only in space2
        assert!(local_space1
            .lookup_handle_in_tree(&test_label("bob"), tip1)
            .await
            .unwrap()
            .is_none());
        assert!(local_space2
            .lookup_handle_in_tree(&test_label("bob"), tip2)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_status() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        // Initially no commits
        let status = local_space.status().await.unwrap();
        assert_eq!(status.commitments, 0);
        assert_eq!(status.staged_handles, 0);

        // Add and commit
        let req = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req).await.unwrap();
        local_space.commit(false).await.unwrap();

        let status = local_space.status().await.unwrap();
        assert_eq!(status.commitments, 1);
        assert_eq!(status.staged_handles, 0);
    }

    #[tokio::test]
    async fn test_zk_batch_verified_by_guest() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        // First commit
        let req1 = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req1).await.unwrap();
        local_space.commit(false).await.unwrap();

        // Second commit - this will use ZK validation
        let req2 = make_request("bob@example", &[0x02; 25]);
        local_space.add_request(&req2).await.unwrap();

        let (exclusion_proof, batch) = local_space.prepare_zk_input().await.unwrap();
        assert!(exclusion_proof.is_some());

        let zk_batch = batch.to_zk_input();
        let commitment =
            libveritas_zk::guest::run(exclusion_proof.unwrap(), zk_batch, STEP_ID, FOLD_ID)
                .unwrap();

        assert_ne!(commitment.initial_root, [0u8; 32]);
        assert_ne!(commitment.final_root, [0u8; 32]);
        assert_ne!(commitment.initial_root, commitment.final_root);
    }
}


fn get_snapshot_for_tip(db: &Database<Sha256Hasher>, tip: [u8;32]) -> anyhow::Result<ReadTransaction<Sha256Hasher>> {
    for snapshot in db.iter() {
        let mut snap = snapshot?;
        let root = snap.compute_root()
            .map_err(|e| anyhow!("could not compute root for snapshot: {}", e))?;
        if root == tip {
            return Ok(snap);
        }
    }
    Err(anyhow!("no snapshot for {}", hex::encode(&tip)))
}

fn rollback_local_commitment(db: &Database<Sha256Hasher>, root: [u8; 32]) -> anyhow::Result<()> {
    let mut found = false;

    for snapshot in db.iter() { // newest -> oldest
        let mut snap = snapshot?;
        let current_root = snap.compute_root()
            .map_err(|e| anyhow!("could not compute root for snapshot: {e}"))?;

        if found {
            // This is the first snapshot older than the target
            snap.rollback()?;
            return Ok(());
        }

        if current_root == root {
            found = true;
        }
    }

    if found {
        // Root was the oldest snapshot, nothing before it
        db.reset()?;
        return Ok(());
    }

    Err(anyhow!("rollback: no snapshot for {}", hex::encode(&root)))
}
