//! Operator - the main entry point for subs operations.
//!
//! Combines local space management with on-chain RPC operations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::core::{
    CompressInput, HealthWarning, LocalSpace, ProvingRequest, SkippedEntry, SpaceStatus,
};
use crate::HandleRequest;
use anyhow::anyhow;
use bitcoin::hashes::{sha256, Hash as BitcoinHash};
use bitcoin::{FeeRate, ScriptBuf, Txid};
use fabric::anchor::AnchorSets;
use fabric::client::{Fabric, Badge};
use libveritas::cert::{Certificate, CertificateChain, ChainProofRequestUtils, NumsSubtree, SpacesSubtree, Witness};
use libveritas::msg::{ChainProof, Message};
use libveritas::{ProvableOption, SovereigntyState, Zone};
use libveritas::builder::MessageBuilder;
use libveritas::sip7::RecordSet;
use spacedb::subtree::SubTree;
use spacedb::{NodeHasher, Sha256Hasher};
use spaces_client::jsonrpsee::http_client::HttpClient;
use spaces_client::rpc::{CommitParams, RpcClient, RpcWalletRequest, RpcWalletTxBuilder};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{Bytes, FullSpaceOut};
use spaces_nums::num_id::NumId;
use spaces_nums::FullNumOut;
use spaces_nums::{ChainProofRequest, RootAnchor};
use spaces_protocol::sname::{SName, NameLike};

pub struct Sha256;

pub enum FullSubjectOut {
    Space(FullSpaceOut),
    Num(FullNumOut)
}

impl FullSubjectOut {
    pub fn script_pubkey(&self) -> &ScriptBuf {
        match self {
            FullSubjectOut::Space(s) => &s.spaceout.script_pubkey,
            FullSubjectOut::Num(n) => &n.numout.script_pubkey,
        }
    }

}
pub struct LiveSpaceInfo {
    pub space: SLabel,
    pub sptr: NumId,
    pub tip: Option<spaces_nums::Commitment>,
    pub fso: FullSubjectOut,
    pub fdo: FullNumOut,
    pub local: Arc<LocalSpace>,
}

impl spaces_protocol::hasher::KeyHasher for Sha256 {
    fn hash(data: &[u8]) -> spaces_protocol::hasher::Hash {
        Sha256Hasher::hash(data)
    }
}

/// Status of an on-chain commit
#[derive(Debug, Clone)]
pub enum CommitStatus {
    /// No pending commit
    None,
    /// Commit broadcast, waiting for confirmation
    Pending { txid: Txid, expected_root: [u8; 32] },
    /// Commit mined but not yet finalized
    Confirmed {
        txid: Txid,
        block_height: u32,
        confirmations: u32,
    },
    /// Commit finalized (144+ confirmations)
    Finalized { block_height: u32 },
}

/// A resolved zone with its verification badge.
#[derive(Clone, serde::Serialize)]
pub struct ResolvedZone {
    #[serde(flatten)]
    pub zone: Zone,
    pub badge: String,
}

/// Exported verification bundle containing the binary message and root anchors.
pub struct VerificationBundle {
    pub message: Vec<u8>,
    pub anchors: Vec<RootAnchor>,
}

/// Handle information for API responses
#[derive(Debug, Clone, serde::Serialize)]
pub struct HandleInfo {
    pub name: String,
    pub script_pubkey: String,
    pub status: String,
    pub commitment_root: Option<String>,
    pub commitment_idx: Option<usize>,
    pub publish_status: Option<String>,
    pub parked: bool,
    /// Testing only: auto-generated WIF key (not for production use)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_private_key: Option<String>,
}

/// Paginated list of handles
#[derive(Debug, Clone, serde::Serialize)]
pub struct HandlesListResult {
    pub handles: Vec<HandleInfo>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
    pub total_pages: usize,
}

/// Pipeline step state
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Complete,
    InProgress,
    Pending,
    Skipped,
}

/// Commitment pipeline status for the UI stepper
#[derive(Debug, Clone, serde::Serialize)]
pub struct PipelineStatus {
    /// Whether there's a pending commitment being processed
    pub has_pending: bool,
    /// Number of staged handles ready to commit
    pub staged_count: usize,
    /// Commitment index (0 = initial)
    pub commitment_idx: Option<usize>,
    /// Root hash of the commitment
    pub root: Option<String>,
    /// Transaction ID (if broadcast)
    pub txid: Option<String>,
    /// Steps and their states
    pub steps: PipelineSteps,
    /// Current active step name
    pub current_step: Option<String>,
    /// Additional status message
    pub message: Option<String>,
    /// Number of handles that need certificate publishing
    pub unpublished: usize,
    /// Number of pending proofs across all commitments
    pub pending_proofs: usize,
    /// Proving estimate for the current commitment (JSON EstimateResult)
    pub estimate: Option<serde_json::Value>,
}

impl LiveSpaceInfo {
    pub async fn issue_cert(
        &self,
        rpc: &HttpClient,
        wallet: &str,
        name: &SName,
    ) -> anyhow::Result<Certificate> {
        let label_count = name.label_count();
        if label_count == 0 {
            return Err(anyhow!("Cannot issue cert for empty name"));
        }
        let tip = self.tip.as_ref().map(|c| c.state_root);

        if label_count == 1 {
            let Some(tip) = tip else {
                return Ok(Certificate::new(
                    SName::from_space(&self.space),
                    Witness::Root { receipt: None },
                ));
            };
            return Ok(self
                .local
                .issue_cert(&SName::from_space(&self.space), tip)
                .await?);
        }
        if label_count != 2 {
            return Err(anyhow!("Cannot issue cert for more than two labels"));
        }

        let sub = name.subspace().unwrap();
        let is_final = self.local.lookup_handle_in_tree(&sub, tip).await?.is_some();
        if is_final {
            return self.local.issue_cert(&name, tip.unwrap()).await;
        }

        // temp cert
        let Some(script_pubkey) = self.local.get_handle_spk(&sub).await? else {
            return Err(anyhow!("handle {} neither committed nor staged", name));
        };
        let zone = Zone {
            anchor: 0,
            sovereignty: SovereigntyState::Dependent,
            canonical: name.clone(),
            handle: name.clone(),
            alias: None,
            num_id: Some(NumId::from_spk::<Sha256>(script_pubkey.clone())),
            script_pubkey,
            records: RecordSet::empty(),
            fallback_records: RecordSet::empty(),
            delegate: ProvableOption::Unknown,
            commitment: ProvableOption::Unknown,
        };

        log::info!("signing with sptr: {}", self.sptr);
        let signature_bytes = rpc
            .wallet_sign_schnorr(
                wallet,
                spaces_wallet::Subject::NumId(self.sptr),
                Bytes::new(zone.signing_bytes()),
            )
            .await
            .map_err(|e| anyhow!("failed to sign zone: {}", e))?;

        let sig_array: [u8; 64] = signature_bytes
            .to_vec()
            .try_into()
            .map_err(|_| anyhow!("signature must be 64 bytes"))?;

        let cert = self
            .local
            .issue_temp_cert(&zone.handle, tip, sig_array)
            .await?;
        Ok(cert)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PipelineSteps {
    pub local: StepState,
    pub proving: StepState,
    pub broadcast: StepState,
    pub confirmed: StepState,
    pub finalized: StepState,
    pub published: StepState,
}

/// The main entry point for subs operations.
///
/// Combines local space management with on-chain RPC operations.
pub struct Operator {
    data_dir: PathBuf,
    wallet: String,
    rpc: Option<HttpClient>,
    fabric: Option<Fabric>,
    fabric_seeds: Vec<String>,
    spaces: Arc<Mutex<HashMap<SLabel, Arc<LocalSpace>>>>,
}

impl Operator {
    /// Create a new Operator with RPC client.
    ///
    /// # Arguments
    /// * `data_dir` - Directory for storing space data
    /// * `wallet` - Wallet name for signing operations
    /// * `rpc` - RPC client for chain interaction
    pub fn new(data_dir: PathBuf, wallet: impl Into<String>, rpc: HttpClient) -> Self {
        Self {
            data_dir,
            wallet: wallet.into(),
            rpc: Some(rpc),
            spaces: Arc::new(Mutex::new(HashMap::new())),
            fabric: None,
            fabric_seeds: Vec::new(),
        }
    }

    /// Create a new Operator for offline operations only.
    ///
    /// On-chain operations will fail without an RPC client.
    pub fn offline(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            wallet: String::new(),
            rpc: None,
            fabric: None,
            fabric_seeds: Vec::new(),
            spaces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the fabric client with default seeds.
    pub fn with_fabric(mut self) -> Self {
        self.fabric = Some(Fabric::new());
        // empty means default seeds
        self.fabric_seeds = Vec::new();
        self
    }

    /// Set the fabric client with custom bootstrap seed URLs.
    pub fn with_fabric_seeds(mut self, seeds: &[&str]) -> Self {
        self.fabric = Some(Fabric::with_seeds(seeds));
        self.fabric_seeds = seeds.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    pub fn wallet(&self) -> &str {
        &self.wallet
    }

    pub fn rpc(&self) -> Option<&HttpClient> {
        self.rpc.as_ref()
    }

    fn require_rpc(&self) -> anyhow::Result<&HttpClient> {
        self.rpc
            .as_ref()
            .ok_or_else(|| anyhow!("RPC client required for this operation"))
    }

    fn require_fabric(&self) -> anyhow::Result<&Fabric> {
        self.fabric
            .as_ref()
            .ok_or_else(|| anyhow!("Fabric client required for this operation"))
    }

    /// Export a verifiable message for a handle: the binary message (.spacemsg)
    /// and the root anchors needed to verify it.
    /// Uses a fresh Fabric instance to avoid cached data missing proof receipts.
    pub async fn export_message(&self, handle: &str) -> anyhow::Result<VerificationBundle> {
        self.require_fabric()?;
        let rpc = self.require_rpc()?;

        // Create a fresh fabric instance to avoid stale cache
        let fabric = if self.fabric_seeds.is_empty() {
            Fabric::new()
        } else {
            let refs: Vec<&str> = self.fabric_seeds.iter().map(|s| s.as_str()).collect();
            Fabric::with_seeds(&refs)
        };

        let anchors = rpc.get_root_anchors().await
            .map_err(|e| anyhow!("failed to fetch root anchors: {}", e))?;
        let sets = AnchorSets::from_anchors(anchors.clone());
        fabric.trust_from_set(sets.latest()
            .ok_or_else(|| anyhow!("no anchor sets available"))?)?;

        let raw = fabric.export(handle).await
            .map_err(|e| anyhow!("failed to export certificate chain: {}", e))?;
        let spacecert = CertificateChain::from_slice(&raw)
            .map_err(|e| anyhow!("invalid certificate chain: {}", e))?;

        let mut builder = MessageBuilder::new();
        builder.add_chain(spacecert);

        let req = builder.chain_proof_request();
        let raw_proof = fabric.prove(&req).await
            .map_err(|e| anyhow!("failed to build chain proof: {}", e))?;
        let proof = ChainProof::from_slice(&raw_proof)
            .map_err(|e| anyhow!("invalid chain proof: {}", e))?;

        let (msg, _) = builder.build(proof)
            .map_err(|e| anyhow!("failed to build message: {}", e))?;

        Ok(VerificationBundle {
            message: msg.to_bytes(),
            anchors,
        })
    }

    /// Resolve a handle via the certrelay network and return its verified zone.
    pub async fn resolve(&self, handles: &[&str]) -> anyhow::Result<Vec<ResolvedZone>> {
        let fabric = self.require_fabric()?;

        // Refresh anchors before querying so we have the latest chain state
        let anchors = self.require_rpc()?.get_root_anchors().await?;
        let sets = AnchorSets::from_anchors(anchors);
        _ = fabric.trust_from_set(sets.latest().unwrap())?;

        let rb = fabric.resolve_all(handles).await
            .map_err(|e| anyhow!("resolve error: {}", e))?;

        let results = rb.zones.into_iter().map(|zone| {
            let badge = fabric.badge_for(zone.sovereignty, &rb.roots);
            ResolvedZone {
                badge: match badge {
                    Badge::Orange => "orange",
                    Badge::Unverified => "unverified",
                    Badge::None => "none",
                }.to_string(),
                zone,
            }
        }).collect();

        Ok(results)
    }

    /// Get a loaded space by name. Briefly locks the spaces map.
    fn get_local_space(&self, space: &SLabel) -> anyhow::Result<Arc<LocalSpace>> {
        self.spaces
            .lock()
            .unwrap()
            .get(space)
            .cloned()
            .ok_or_else(|| anyhow!("space '{}' not loaded", space))
    }

    /// Check if the wallet can operate on a space (owns the delegated sptr).
    async fn can_operate(&self, space: &SLabel) -> anyhow::Result<bool> {
        use spaces_client::rpc::RpcClient;

        let rpc = self.require_rpc()?;
        let result = rpc
            .wallet_can_operate(&self.wallet, space.clone().into())
            .await
            .map_err(|e| {
                anyhow!(
                    "could not check if wallet can operate on '{}': {}",
                    space,
                    e
                )
            })?;
        Ok(result)
    }

    /// Load a space from disk without validation.
    ///
    /// This is used for loading existing spaces at startup.
    /// Does not check if the wallet can operate on the space.
    async fn load_space_unchecked(&self, space: &SLabel) -> anyhow::Result<()> {
        {
            let spaces_guard = self.spaces.lock().unwrap();
            if spaces_guard.contains_key(space) {
                return Ok(());
            }
        }

        let space_dir = self.data_dir.join(space.to_string());
        let local_space = LocalSpace::new(space.clone(), space_dir).await?;

        let mut spaces_guard = self.spaces.lock().unwrap();
        if !spaces_guard.contains_key(space) {
            spaces_guard.insert(space.clone(), Arc::new(local_space));
        }
        Ok(())
    }

    /// Load or create a space.
    ///
    /// Opens an existing space or creates a new one if it doesn't exist.
    /// For new spaces, verifies the wallet can operate on the space first.
    pub async fn load_or_create_space(&self, space: &SLabel) -> anyhow::Result<()> {
        // Check if already loaded
        {
            let spaces_guard = self.spaces.lock().unwrap();
            if spaces_guard.contains_key(space) {
                return Ok(());
            }
        }

        // Check if space already exists on disk - if so, just load it
        let space_dir = self.data_dir.join(space.to_string());
        let exists_on_disk = space_dir.join("subs.db").exists();

        // For NEW spaces (not on disk), verify we can operate on this space
        if !exists_on_disk && self.rpc.is_some() {
            let can_op = self.can_operate(space).await?;
            if !can_op {
                return Err(anyhow!(
                    "space '{}' is not delegated to wallet '{}'",
                    space,
                    self.wallet
                ));
            }
        }

        let local_space = LocalSpace::new(space.clone(), space_dir).await?;
        local_space.check_consistency().await?;

        let mut spaces_guard = self.spaces.lock().unwrap();
        // Double-check in case another task created it
        if !spaces_guard.contains_key(space) {
            spaces_guard.insert(space.clone(), Arc::new(local_space));
        }
        Ok(())
    }

    /// List all loaded spaces.
    pub fn list_spaces(&self) -> Vec<SLabel> {
        self.spaces.lock().unwrap().keys().cloned().collect()
    }

    /// Get status of a loaded space.
    /// Check if a space has an unknown on-chain commitment.
    async fn check_commitment_health(&self, space: &SLabel) -> anyhow::Result<Option<HealthWarning>> {
        let Some(rpc) = &self.rpc else { return Ok(None) };
        use spaces_client::rpc::RpcClient;

        let on_chain = rpc.get_commitment(space.clone().into(), None).await?;
        let Some(chain) = on_chain else { return Ok(None) };

        let chain_root = hex::encode(chain.state_root);
        let local_space = self.get_local_space(space)?;
        let known = local_space.storage().get_commitment_by_root(&chain_root).await?.is_some();

        if known {
            Ok(None)
        } else {
            const FINALITY: u32 = 144;
            let tip_height = rpc.get_server_info().await?.tip.height;
            let confirmations = tip_height.saturating_sub(chain.block_height);
            let blocks_until_finalized = FINALITY.saturating_sub(confirmations);

            // Rollback only makes sense if not finalized AND prev_root
            // is either None (genesis) or matches a known local commitment
            let rollback_lands_known = match chain.prev_root {
                None => true,
                Some(prev) => local_space.storage().get_commitment_by_root(&hex::encode(prev)).await?.is_some(),
            };
            let can_rollback = confirmations < FINALITY && rollback_lands_known;

            Ok(Some(HealthWarning {
                message: "This space has an on-chain commitment that is not tracked locally. \
                          All actions are disabled until recovery is supported. \
                          To recover in the future, you will need the .sdb file \
                          (name database) and the certificate that was used to prove it.".to_string(),
                chain_root,
                block_height: chain.block_height,
                commit_txid: None,
                can_rollback,
                blocks_until_finalized,
            }))
        }
    }

    /// Bail if the space has an untracked on-chain commitment.
    async fn require_healthy(&self, space: &SLabel) -> anyhow::Result<()> {
        if let Some(w) = self.check_commitment_health(space).await? {
            return Err(anyhow!("{}", w.message));
        }
        Ok(())
    }

    pub async fn get_space_status(&self, space: &SLabel) -> anyhow::Result<SpaceStatus> {
        let local_space = self.get_local_space(space)?;
        let mut status = local_space.status().await?;
        status.health_warning = self.check_commitment_health(space).await?;
        Ok(status)
    }

    /// List handles for a space with pagination, optional search and filter.
    pub async fn list_handles(
        &self,
        space: &SLabel,
        page: usize,
        per_page: usize,
        search: Option<String>,
        filter: Option<String>,
    ) -> anyhow::Result<HandlesListResult> {
        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        let total = storage.handle_count_filtered(search.clone(), filter.clone()).await?;
        let offset = (page.saturating_sub(1)) * per_page;
        let handles = storage.list_handles_filtered(offset, per_page, search, filter).await?;

        let total_pages = (total + per_page - 1) / per_page.max(1);

        Ok(HandlesListResult {
            handles: handles
                .into_iter()
                .map(|h| HandleInfo {
                    name: h.name,
                    script_pubkey: hex::encode(&h.script_pubkey),
                    status: if h.commitment_root.is_some() {
                        "committed".to_string()
                    } else {
                        "staged".to_string()
                    },
                    commitment_root: h.commitment_root,
                    commitment_idx: h.commitment_idx,
                    publish_status: h.publish_status,
                    parked: h.parked,
                    dev_private_key: h.dev_private_key,
                })
                .collect(),
            total,
            page,
            per_page,
            total_pages,
        })
    }

    /// Get handles by commitment root.
    pub async fn get_handles_by_commitment(
        &self,
        space: &SLabel,
        root: &str,
    ) -> anyhow::Result<Vec<HandleInfo>> {
        let local_space = self.get_local_space(space)?;
        let handles = local_space
            .storage()
            .list_handles_by_commitment(root)
            .await?;

        Ok(handles
            .into_iter()
            .map(|h| HandleInfo {
                name: h.name,
                script_pubkey: hex::encode(&h.script_pubkey),
                status: "committed".to_string(),
                commitment_root: h.commitment_root,
                commitment_idx: h.commitment_idx,
                publish_status: h.publish_status,
                parked: h.parked,
                dev_private_key: h.dev_private_key,
            })
            .collect())
    }

    /// Get a single handle by name within a space.
    pub async fn get_handle_info(
        &self,
        space: &SLabel,
        name: &str,
    ) -> anyhow::Result<Option<HandleInfo>> {
        let local_space = self.get_local_space(space)?;
        let handle = local_space.storage().get_handle(name).await?;
        Ok(handle.map(|h| HandleInfo {
            name: h.name,
            script_pubkey: hex::encode(&h.script_pubkey),
            status: if h.commitment_root.is_some() {
                "committed".to_string()
            } else {
                "staged".to_string()
            },
            commitment_root: h.commitment_root,
            commitment_idx: h.commitment_idx,
            publish_status: h.publish_status,
            parked: h.parked,
            dev_private_key: h.dev_private_key,
        }))
    }

    /// List all spaces with subs.db files on disk.
    pub fn list_spaces_from_disk(&self) -> anyhow::Result<Vec<SLabel>> {
        let mut spaces = Vec::new();
        if !self.data_dir.exists() {
            return Ok(spaces);
        }
        for entry in std::fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.join("subs.db").exists() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Ok(space) = SLabel::try_from(name) {
                        spaces.push(space);
                    }
                }
            }
        }
        Ok(spaces)
    }

    /// Load all spaces from disk.
    ///
    /// Loads existing space data without validating wallet delegation.
    /// Spaces that fail to load are logged and skipped.
    pub async fn load_all_spaces(&self) -> anyhow::Result<()> {
        let spaces = self.list_spaces_from_disk()?;
        for space in spaces {
            if let Err(e) = self.load_space_unchecked(&space).await {
                log::warn!("Failed to load space '{}': {}", space, e);
            }
        }
        Ok(())
    }

    /// List spaces delegated to this wallet that are not yet being operated.
    pub async fn list_delegated_spaces(&self) -> anyhow::Result<Vec<SLabel>> {
        let rpc = self.require_rpc()?;
        let response = rpc
            .wallet_list_nums(&self.wallet, None)
            .await
            .map_err(|e| anyhow!("failed to list ptrs: {}", e))?;

        let operated: std::collections::HashSet<SLabel> = {
            self.spaces.lock().unwrap().keys().cloned().collect()
        };

        let mut delegated = Vec::new();
        for entry in response.nums {
            if let Some(space) = entry.delegating_for {
                if !operated.contains(&space) {
                    delegated.push(space);
                }
            }
        }
        delegated.sort();
        delegated.dedup();
        Ok(delegated)
    }

    /// Get status of all spaces.
    pub async fn status(&self) -> anyhow::Result<crate::core::StatusResult> {
        self.load_all_spaces().await?;

        let local_spaces: Vec<Arc<LocalSpace>> =
            { self.spaces.lock().unwrap().values().cloned().collect() };

        let mut statuses = Vec::new();
        for local_space in local_spaces {
            statuses.push(local_space.status().await?);
        }
        Ok(crate::core::StatusResult { spaces: statuses })
    }

    /// Stage a handle request.
    ///
    /// The handle will be added to the staging area for the space.
    /// Returns None if successful, or SkippedEntry if the handle was skipped.
    pub async fn stage_request(
        &self,
        request: HandleRequest,
    ) -> anyhow::Result<Option<SkippedEntry>> {
        let space = request
            .handle
            .space()
            .ok_or_else(|| anyhow!("handle must have a space"))?;

        // Ensure space is loaded
        self.load_or_create_space(&space).await?;

        let local_space = self.get_local_space(&space)?;
        local_space.add_request(&request).await
    }

    /// Add multiple handle requests to staging.
    ///
    /// Groups requests by space and stages them. Returns results per space.
    pub async fn add_requests(
        &self,
        requests: Vec<HandleRequest>,
    ) -> anyhow::Result<crate::core::AddResult> {
        use crate::core::{AddResult, SpaceAddResult};

        if requests.is_empty() {
            return Err(anyhow!("No requests to add"));
        }

        // Group requests by space
        let mut by_space: HashMap<SLabel, Vec<HandleRequest>> = HashMap::new();
        for req in requests {
            let space = req
                .handle
                .space()
                .ok_or_else(|| anyhow!("handle must have a space"))?;
            by_space.entry(space).or_default().push(req);
        }

        let mut results = Vec::new();
        let mut total_added = 0;

        for (space, space_requests) in by_space {
            // Ensure space is loaded
            self.load_or_create_space(&space).await?;
            self.require_healthy(&space).await?;

            let local_space = self.get_local_space(&space)?;

            let mut added = Vec::new();
            let mut skipped = Vec::new();

            for req in space_requests {
                match local_space.add_request(&req).await? {
                    Some(s) => skipped.push(s),
                    None => added.push(req.handle),
                }
            }

            total_added += added.len();
            results.push(SpaceAddResult {
                space,
                added,
                skipped,
            });
        }

        Ok(AddResult {
            by_space: results,
            total_added,
        })
    }

    /// Check if a local commit can be made for a space.
    ///
    /// Returns an error message if commit is blocked, None if allowed.
    /// Note: If RPC is not available, on-chain finalization checks are skipped.
    pub async fn can_commit_local(&self, space: &SLabel) -> anyhow::Result<Option<String>> {
        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        let last_commitment = storage.get_last_commitment().await?;
        let staging_count = storage.staged_count().await?;

        if staging_count == 0 {
            return Ok(Some("no staged changes to commit".to_string()));
        }

        let Some(commitment) = last_commitment else {
            // No previous commits, can always commit
            return Ok(None);
        };

        // Check if previous commitment needs proving (non-initial commits need proof)
        if commitment.prev_root.is_some() {
            // This was a non-initial commit, needs proof
            let has_proof = commitment.step_receipt_id.is_some()
                && (commitment.aggregate_receipt_id.is_some() || commitment.idx == 1);
            if !has_proof {
                return Ok(Some(format!(
                    "commitment #{} needs proving before new commit",
                    commitment.idx
                )));
            }
        }

        // On-chain finalization checks require RPC
        if let Some(rpc) = &self.rpc {
            // Check on-chain status if there's a commit_txid
            if commitment.commit_txid.is_some() {
                // Always check on-chain status via RPC
                let mut expected_root = [0u8; 32];
                hex::decode_to_slice(&commitment.root, &mut expected_root)
                    .map_err(|e| anyhow!("invalid root: {}", e))?;

                let on_chain = rpc.get_commitment(space.clone().into(), None).await?;

                if let Some(commitment) = on_chain {
                    if commitment.state_root == expected_root {
                        // Commit is on-chain, check finalization (144 blocks + 6 safety)
                        let tip = rpc.get_server_info().await?.tip.height;
                        let confirmations = tip.saturating_sub(commitment.block_height);
                        if confirmations < 150 {
                            return Ok(Some(format!(
                                "previous commit needs {} more confirmations ({}/150)",
                                150 - confirmations,
                                confirmations
                            )));
                        }
                        // Commit is finalized, can proceed
                    } else {
                        // Chain has different root - commit may have been replaced
                        return Ok(Some(
                            "on-chain commitment root doesn't match local entry".to_string(),
                        ));
                    }
                } else {
                    // Not on-chain yet
                    return Ok(Some(
                        "previous commit pending confirmation on-chain".to_string(),
                    ));
                }
            } else if commitment.idx > 0 {
                // Non-initial commitment without commit_txid means not committed on-chain yet
                return Ok(Some(
                    "previous commit not yet submitted on-chain".to_string(),
                ));
            }
        }

        Ok(None)
    }

    /// Commit staged changes locally.
    ///
    /// This validates and commits staged entries to the local database.
    /// For non-initial commits, this creates a proving request that must be
    /// fulfilled before the commit can be submitted on-chain.
    pub async fn commit_local(
        &self,
        space: &SLabel,
    ) -> anyhow::Result<crate::core::SpaceCommitResult> {
        self.require_healthy(space).await?;
        // Check if we can commit
        if let Some(reason) = self.can_commit_local(space).await? {
            return Err(anyhow!("cannot commit: {}", reason));
        }

        let local_space = self.get_local_space(space)?;
        local_space.commit(false).await
    }

    /// Rollback the last unbroadcast local commitment.
    pub async fn rollback_local(&self, space: &SLabel) -> anyhow::Result<()> {
        let local_space = self.get_local_space(space)?;
        local_space.rollback_local().await
    }

    /// Park or unpark staged handles by name list or by search/filter.
    pub async fn set_parked(
        &self,
        space: &SLabel,
        names: &[String],
        parked: bool,
        search: Option<String>,
        filter: Option<String>,
    ) -> anyhow::Result<usize> {
        let local_space = self.get_local_space(space)?;
        local_space.storage().set_parked(names, parked, search, filter).await
    }

    pub async fn remove_staged(
        &self,
        space: &SLabel,
        names: &[String],
        search: Option<String>,
        filter: Option<String>,
    ) -> anyhow::Result<usize> {
        let local_space = self.get_local_space(space)?;
        local_space.storage().remove_staged_handles(names, search, filter).await
    }

    /// Get the next proving request for a space.
    ///
    /// Returns None if no proving is needed.
    pub async fn get_next_proving_request(
        &self,
        space: &SLabel,
    ) -> anyhow::Result<Option<ProvingRequest>> {
        let local_space = self.get_local_space(space)?;
        local_space.get_next_proving_request().await
    }

    /// Fulfill a proving request with a receipt.
    ///
    /// Verifies and stores the receipt.
    pub async fn fulfill_request(
        &self,
        space: &SLabel,
        request: &ProvingRequest,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let local_space = self.get_local_space(space)?;
        local_space
            .save_proving_receipt(request, receipt_bytes)
            .await
    }

    /// Fulfill a proving request by commitment ID and type (for binary endpoint)
    pub async fn fulfill_request_by_id(
        &self,
        space: &SLabel,
        commitment_id: i64,
        is_fold: bool,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let local_space = self.get_local_space(space)?;
        local_space
            .save_proving_receipt_by_id(commitment_id, is_fold, receipt_bytes)
            .await
    }

    /// Save a proving estimate for a commitment.
    pub async fn save_estimate(
        &self,
        space: &SLabel,
        commitment_id: i64,
        estimate_json: &str,
    ) -> anyhow::Result<()> {
        let local_space = self.get_local_space(space)?;
        local_space.save_estimate(commitment_id, estimate_json).await
    }

    /// Get input for SNARK compression.
    pub async fn get_compress_input(
        &self,
        space: &SLabel,
    ) -> anyhow::Result<Option<CompressInput>> {
        let local_space = self.get_local_space(space)?;
        local_space.get_compress_input().await
    }

    /// Save a groth16 (SNARK) receipt.
    pub async fn save_snark(&self, space: &SLabel, receipt_bytes: &[u8]) -> anyhow::Result<()> {
        let local_space = self.get_local_space(space)?;
        local_space.save_groth16_receipt(receipt_bytes).await
    }

    /// Commit the latest local entry on-chain.
    ///
    /// Broadcasts a transaction to commit the state root on-chain.
    /// Returns the transaction ID. If fee_rate is None, uses wallet default.
    pub async fn commit(&self, space: &SLabel, fee_rate: Option<FeeRate>) -> anyhow::Result<Txid> {
        self.require_healthy(space).await?;
        // Verify we can still operate on this space (delegation may have been revoked)
        let can_op = self.can_operate(space).await?;
        if !can_op {
            return Err(anyhow!(
                "space '{}' is not delegated to wallet '{}' (delegation may have been revoked)",
                space,
                self.wallet
            ));
        }

        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        // Get the latest commitment's root
        let commitment = storage
            .get_last_commitment()
            .await?
            .ok_or_else(|| anyhow!("no commitments to broadcast"))?;

        // Check if already has a txid
        if commitment.commit_txid.is_some() {
            return Err(anyhow!("commitment already has a pending broadcast"));
        }

        // For non-initial commitments, check that proving is done
        if commitment.prev_root.is_some() {
            let has_proof = commitment.step_receipt_id.is_some();
            if !has_proof {
                return Err(anyhow!(
                    "commitment needs proving before on-chain broadcast"
                ));
            }
        }

        let mut root_bytes = [0u8; 32];
        hex::decode_to_slice(&commitment.root, &mut root_bytes)
            .map_err(|e| anyhow!("invalid root: {}", e))?;

        // Broadcast the commit transaction
        let rpc = self.require_rpc()?;
        let commit_request = RpcWalletRequest::Commit(CommitParams {
            subject: space.clone().into(),
            root: Some(sha256::Hash::from_slice(&root_bytes)?),
        });

        let response = rpc
            .wallet_send_request(
                &self.wallet,
                RpcWalletTxBuilder {
                    bidouts: None,
                    requests: vec![commit_request],
                    fee_rate,
                    dust: None,
                    force: false,
                    confirmed_only: false,
                    skip_tx_check: false,
                },
            )
            .await?;

        // Check for errors
        for tx in &response.result {
            if let Some(e) = tx.error.as_ref() {
                let s = e
                    .iter()
                    .map(|(k, v)| format!("{k}:{v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(anyhow!("commit failed: {}", s));
            }
        }

        let txid: Txid = response
            .result
            .first()
            .map(|r| r.txid)
            .ok_or_else(|| anyhow!("no txid in response"))?;

        // Store the txid
        storage
            .update_commitment_txid(commitment.id, &txid.to_string())
            .await?;

        Ok(txid)
    }

    /// Get the status of the on-chain commit for a space.
    pub async fn get_commit_status(&self, space: &SLabel) -> anyhow::Result<CommitStatus> {
        let local_space = self.get_local_space(space)?;
        let db_commitment = local_space.storage().get_last_commitment().await?;

        let Some(db_commitment) = db_commitment else {
            return Ok(CommitStatus::None);
        };

        let Some(txid_str) = db_commitment.commit_txid.clone() else {
            return Ok(CommitStatus::None);
        };

        let txid: Txid = txid_str
            .parse()
            .map_err(|e: bitcoin::hex::HexToArrayError| anyhow!("invalid txid: {}", e))?;

        let mut expected_root = [0u8; 32];
        hex::decode_to_slice(&db_commitment.root, &mut expected_root)
            .map_err(|e| anyhow!("invalid root: {}", e))?;

        // Check on-chain state
        let rpc = self.require_rpc()?;
        let on_chain = rpc.get_commitment(space.clone().into(), None).await?;

        if let Some(chain_commitment) = on_chain {
            if chain_commitment.state_root == expected_root {
                let tip = rpc.get_server_info().await?.tip.height;
                let confirmations = tip.saturating_sub(chain_commitment.block_height);

                if confirmations >= 150 {
                    return Ok(CommitStatus::Finalized {
                        block_height: chain_commitment.block_height,
                    });
                } else {
                    return Ok(CommitStatus::Confirmed {
                        txid,
                        block_height: chain_commitment.block_height,
                        confirmations,
                    });
                }
            }
        }

        // Not on-chain yet
        Ok(CommitStatus::Pending {
            txid,
            expected_root,
        })
    }

    /// Get pipeline status for UI stepper (offline-friendly version).
    pub async fn get_pipeline_status(&self, space: &SLabel) -> anyhow::Result<PipelineStatus> {
        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        // Get the latest commitment and staged count
        let commitment = storage.get_last_commitment().await?;
        let staged_count = storage.staged_count().await?;

        // No commitments yet - show message based on staged count
        let Some(commitment) = commitment else {
            let unpublished = storage.select_handles(crate::storage::HandleSelector::Unpublished(None)).await?.len();
            let message = if staged_count > 0 {
                Some(format!(
                    "{} handle(s) staged. Ready to commit.",
                    staged_count
                ))
            } else {
                Some("Stage handles to start a new commitment.".to_string())
            };
            return Ok(PipelineStatus {
                has_pending: false,
                staged_count,
                commitment_idx: None,
                root: None,
                txid: None,
                steps: PipelineSteps {
                    local: StepState::Pending,
                    proving: StepState::Pending,
                    broadcast: StepState::Pending,
                    confirmed: StepState::Pending,
                    finalized: StepState::Pending,
                    published: StepState::Pending,
                },
                current_step: None,
                message,
                unpublished,
                pending_proofs: 0,
                estimate: None,
            });
        };

        let is_initial = commitment.idx == 0;
        let has_proof = if is_initial {
            true
        } else {
            // Proving is complete only when no step or fold proofs are pending
            let next_request = local_space.get_next_proving_request().await?;
            next_request.is_none()
        };
        let is_broadcast = commitment.commit_txid.is_some();

        // Determine step states
        let local = StepState::Complete; // Always complete if commitment exists

        let proving = if is_initial {
            StepState::Skipped
        } else if has_proof {
            StepState::Complete
        } else {
            StepState::InProgress
        };

        // For broadcast/confirmed/finalized/published, check on-chain state
        let (broadcast, confirmed, finalized, published, current_step, message, is_done, confirmed_idx) =
            if !is_broadcast {
                // Not broadcast yet
                if is_initial || has_proof {
                    (
                        StepState::InProgress,
                        StepState::Pending,
                        StepState::Pending,
                        StepState::Pending,
                        Some("broadcast".to_string()),
                        Some("Ready to broadcast".to_string()),
                        false,
                        None,
                    )
                } else {
                    (
                        StepState::Pending,
                        StepState::Pending,
                        StepState::Pending,
                        StepState::Pending,
                        Some("proving".to_string()),
                        Some("Proving required before broadcast".to_string()),
                        false,
                        None,
                    )
                }
            } else {
                // Broadcast - check on-chain status
                let mut on_chain_info: Option<u32> = None; // confirmations

                if let Some(rpc) = &self.rpc {
                    let mut expected_root = [0u8; 32];
                    if hex::decode_to_slice(&commitment.root, &mut expected_root).is_ok() {
                        if let Ok(Some(on_chain)) = rpc.get_commitment(space.clone().into(), None).await {
                            if on_chain.state_root == expected_root {
                                if let Ok(info) = rpc.get_server_info().await {
                                    let confirmations =
                                        info.tip.height.saturating_sub(on_chain.block_height);
                                    on_chain_info = Some(confirmations);
                                }
                            }
                        }
                    }
                }

                match on_chain_info {
                    Some(conf) if conf >= 150 => {
                        // Finalized, check publish status
                        let is_published = commitment.published_at.is_some();
                        if is_published {
                            (
                                StepState::Complete,
                                StepState::Complete,
                                StepState::Complete,
                                StepState::Complete,
                                None,
                                Some("Certificates published".to_string()),
                                true,
                                Some(commitment.idx),
                            )
                        } else {
                            (
                                StepState::Complete,
                                StepState::Complete,
                                StepState::Complete,
                                StepState::InProgress,
                                Some("published".to_string()),
                                Some("Ready to publish certificates".to_string()),
                                false,
                                Some(commitment.idx),
                            )
                        }
                    }
                    Some(conf) => {
                        // Confirmed but not finalized
                        (
                            StepState::Complete,
                            StepState::Complete,
                            StepState::InProgress,
                            StepState::Pending,
                            Some("finalized".to_string()),
                            Some(format!("{}/150 confirmations", conf)),
                            false,
                            Some(commitment.idx),
                        )
                    }
                    None => {
                        // Not confirmed yet
                        (
                            StepState::Complete,
                            StepState::InProgress,
                            StepState::Pending,
                            StepState::Pending,
                            Some("confirmed".to_string()),
                            Some("Waiting for confirmation".to_string()),
                            false,
                            None,
                        )
                    }
                }
            };

        // has_pending is true until fully done (published)
        let has_pending = !is_done;

        // Reset stale temp certs when the on-chain tip has changed,
        // so handles published against an old tip get republished
        if let Some(_) = confirmed_idx {
            storage.reset_stale_temp_certs(Some(&commitment.root)).await?;
        }
        let unpublished = storage.select_handles(crate::storage::HandleSelector::Unpublished(confirmed_idx)).await?.len();

        let commitments = storage.list_commitments().await?;
        let pending_proofs = crate::core::count_pending_proofs(&commitments);
        let estimate = commitment.estimate
            .and_then(|json| serde_json::from_str(&json).ok());

        Ok(PipelineStatus {
            has_pending,
            staged_count,
            commitment_idx: Some(commitment.idx),
            root: Some(commitment.root),
            txid: commitment.commit_txid,
            steps: PipelineSteps {
                local,
                proving,
                broadcast,
                confirmed,
                finalized,
                published,
            },
            current_step,
            message,
            unpublished,
            pending_proofs,
            estimate,
        })
    }

    /// Bump the fee for a pending commit.
    pub async fn bump_commit(&self, space: &SLabel, fee_rate: FeeRate) -> anyhow::Result<Txid> {
        let status = self.get_commit_status(space).await?;

        let txid = match status {
            CommitStatus::Pending { txid, .. } => txid,
            CommitStatus::None => return Err(anyhow!("no pending commit to bump")),
            CommitStatus::Confirmed { .. } | CommitStatus::Finalized { .. } => {
                return Err(anyhow!("commit already confirmed, cannot bump"))
            }
        };

        // Use wallet RBF to bump fee
        let rpc = self.require_rpc()?;
        let responses = rpc
            .wallet_bump_fee(&self.wallet, txid, fee_rate, false)
            .await?;

        let new_txid = responses
            .first()
            .map(|r| r.txid)
            .ok_or_else(|| anyhow!("no txid in bump response"))?;

        // Update stored txid
        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();
        let commitment = storage
            .get_last_commitment()
            .await?
            .ok_or_else(|| anyhow!("no commitment"))?;
        storage
            .update_commitment_txid(commitment.id, &new_txid.to_string())
            .await?;

        Ok(new_txid)
    }

    pub async fn submit_certs(&self, certs: Vec<Certificate>) -> anyhow::Result<()> {
        log::info!("submit_certs: building message for {} certs", certs.len());
        let msg = self.build_message(certs).await?;
        log::info!("submit_certs: message built, broadcasting via fabric");
        let fabric = self.require_fabric()?;
        let relays = fabric
            .bootstrap()
            .await
            .map_err(|e| anyhow!("fabric bootstrap error: {}", e))?;

        log::info!("relays available: {:?}", relays);
        fabric
            .broadcast(&msg.to_bytes())
            .await
            .map_err(|e| anyhow!("Could not broadcast message: {}", e))?;
        log::info!("submit_certs: broadcast OK");
        Ok(())
    }

    pub async fn build_message(&self, certs: Vec<Certificate>) -> anyhow::Result<Message> {
        log::info!("build_message: building chain proof request");
        let req = ChainProofRequest::from_certificates(certs.iter());
        for r in &req.spaces {
            log::info!("chain proof request has space: {}", r);
        }
        let rpc = self.require_rpc()?;
        log::info!("build_message: calling build_chain_proof RPC");
        let res = rpc.build_chain_proof(req, None).await?;
        log::info!("build_message: chain proof received");

        let stree = SubTree::<Sha256Hasher>::from_slice(res.spaces_proof.as_slice())
            .map_err(|e| anyhow!("could not decode spaces proof: {}", e))?;
        let ptree = SubTree::<Sha256Hasher>::from_slice(res.ptrs_proof.as_slice())
            .map_err(|e| anyhow!("could not decode ptrs proof: {}", e))?;

        let chain_proof = ChainProof {
            anchor: res.block,
            spaces: SpacesSubtree(stree),
            nums: NumsSubtree(ptree),
        };
        log::info!("build_message: constructing message from certificates");
        Ok(Message::try_from_certificates(chain_proof, certs)?)
    }

    /// Issue a certificate for a single handle or space.
    ///
    /// Returns `(root_cert, Option<handle_cert>)`:
    /// - For `@space`: returns `(root_cert, None)`
    /// - For `alice@space`: returns `(root_cert, Some(handle_cert))`
    pub async fn issue_cert(
        &self,
        handle: &SName,
    ) -> anyhow::Result<(Certificate, Option<Certificate>)> {
        let certs = self.issue_certs(vec![handle.clone()]).await?;
        let mut iter = certs.into_iter();
        let root_cert = iter.next().ok_or_else(|| anyhow!("missing root cert"))?;
        let handle_cert = iter.next();
        Ok((root_cert, handle_cert))
    }

    pub async fn get_live_space(&self, space: SLabel) -> anyhow::Result<LiveSpaceInfo> {
        let rpc = self.require_rpc()?;

        let Some(fso) = get_subject_out(&rpc, &space).await? else {
            return Err(anyhow!("subject not found: {}", space));
        };
        let tip = rpc
            .get_commitment(space.clone().into(), None)
            .await
            .map_err(|e| anyhow!("could not retrieve commitment tip for {}: {}", space, e))?;
        let sptr = NumId::from_spk::<Sha256>(fso.script_pubkey().clone());
        let Some(fdo) = rpc.get_num(spaces_wallet::Subject::NumId(sptr)).await? else {
            return Err(anyhow!("no delegate {} found for space {}", sptr, space));
        };
        let local = self.get_local_space(&space)?;
        Ok(LiveSpaceInfo {
            space,
            sptr,
            tip,
            fso,
            fdo,
            local,
        })
    }

    pub async fn issue_certs(&self, handles: Vec<SName>) -> anyhow::Result<Vec<Certificate>> {
        let mut certs = Vec::new();
        struct SpaceHandles {
            info: LiveSpaceInfo,
            handles: Vec<SName>,
        }

        let mut by_space = HashMap::new();
        for handle in handles {
            if !handle.is_single_label() && handle.label_count() != 2 {
                return Err(anyhow!("cannot issue cert for handle: {}", handle));
            }
            by_space
                .entry(handle.space().unwrap())
                .or_insert(Vec::new())
                .push(handle);
        }
        let rpc = self.require_rpc()?;
        let mut space_datas = Vec::new();
        for (space, handles) in by_space {
            let info = self.get_live_space(space.clone()).await?;
            space_datas.push(SpaceHandles { info, handles })
        }

        for space_data in space_datas {
            let space = SName::from_space(&space_data.info.space);
            let root_cert = space_data
                .info
                .issue_cert(rpc, &self.wallet, &space)
                .await?;
            certs.push(root_cert);
            for handle in space_data.handles {
                let cert = space_data
                    .info
                    .issue_cert(rpc, &self.wallet, &handle)
                    .await?;
                certs.push(cert);
            }
        }

        Ok(certs)
    }

    /// Publish certificates for unpublished handles, up to `limit` at a time.
    /// If `only` is non-empty, only publish those specific handle names.
    /// Returns (published_count, remaining_count).
    pub async fn publish_certs(&self, space: &SLabel, limit: usize, only: &[String]) -> anyhow::Result<(usize, usize)> {
        self.require_fabric()?;

        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        let live = self.get_live_space(space.clone()).await?;
        let tip = live.tip.as_ref().map(|c| c.state_root);
        let tip_hex = tip.map(hex::encode);

        // Determine confirmed commitment idx from on-chain tip
        let confirmed_idx = if let Some(tip) = tip {
            storage.get_commitment_by_root(&hex::encode(tip)).await?.map(|c| c.idx)
        } else {
            None
        };

        // Reset stale temp certs: handles that were temp-published against
        // an old chain state need to be republished with a fresh chain proof
        let reset = storage.reset_stale_temp_certs(tip_hex.as_deref()).await?;
        if reset > 0 {
            log::info!("[{}] Reset {} stale temp cert(s) for republishing", space, reset);
        }

        let all_handles = storage.select_handles(
            if only.is_empty() {
                crate::storage::HandleSelector::Unpublished(confirmed_idx)
            } else {
                crate::storage::HandleSelector::ByName(only.to_vec())
            }
        ).await?;
        if all_handles.is_empty() {
            return Ok((0, 0));
        }

        let total = all_handles.len();
        let batch: Vec<_> = all_handles.into_iter().take(limit).collect();

        let handle_names: Vec<SName> = batch
            .iter()
            .map(|h| format!("{}@{}", h.name, space.as_str_unprefixed().unwrap()).parse())
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow!("invalid handle name: {}", e))?;

        let count = handle_names.len();
        let certs = self.issue_certs(handle_names).await?;
        self.submit_certs(certs).await?;

        // Determine temp vs final per handle based on confirmed idx
        let mut temp_names = Vec::new();
        let mut final_names = Vec::new();
        for h in &batch {
            let is_final = match (h.commitment_idx, confirmed_idx) {
                (Some(h_idx), Some(c_idx)) if h_idx <= c_idx => true,
                _ => false,
            };
            if is_final {
                final_names.push(h.name.clone());
            } else {
                temp_names.push(h.name.clone());
            }
        }

        if !temp_names.is_empty() {
            storage.mark_handles_published(&temp_names, "temp", tip_hex.as_deref()).await?;
        }
        if !final_names.is_empty() {
            storage.mark_handles_published(&final_names, "final", None).await?;
            // If no more committed handles need publishing, mark commitment as published
            if storage.select_handles(crate::storage::HandleSelector::Unpublished(confirmed_idx)).await?.iter().all(|h| h.commitment_root.is_none()) {
                if let Some(commitment) = storage.get_last_commitment().await? {
                    if commitment.published_at.is_none() {
                        storage.mark_commitment_published(commitment.id).await?;
                    }
                }
            }
        }

        let remaining = total - count;
        Ok((count, remaining))
    }

}

pub async fn get_subject_out(rpc: &HttpClient, subject: &SLabel) -> anyhow::Result<Option<FullSubjectOut>> {
    if subject.is_numeric() {
       let num =  rpc.get_num(subject.clone().into()).await?;
        return Ok(num.map(|n| FullSubjectOut::Num(n)));
    }

    let space =  rpc.get_space(&subject.to_string()).await?;
    Ok(space.map(|s| FullSubjectOut::Space(s)))
}