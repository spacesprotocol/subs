//! Generate test vectors for certrelay testing.
//!
//! Run with: cargo test --test test_vectors -- --nocapture generate_test_vectors
//!
//! This generates static test vectors (anchors + certificates) that can be used
//! to test certrelay without needing a live spaced instance.
//!
//! Test vectors cover different root cert states:
//! 1. Root cert WITHOUT commitment (temporary children, dependent state)
//! 2. Root cert WITH commitment but NOT finalized (pending sovereignty)
//! 3. Root cert WITH commitment, finalized but NOT permanent (sovereign, not permanent)
//! 4. Root cert WITH commitment, finalized AND permanent (sovereign, permanent)

use std::path::PathBuf;
use std::str::FromStr;

use libveritas::cert::Certificate;
use serde::{Serialize, Deserialize};
use spaces_client::rpc::{OperateParams, RpcClient, RpcWalletRequest, RpcWalletTxBuilder};
use spaces_client::wallets::WalletResponse;
use spaces_nums::RootAnchor;
use spaces_protocol::bitcoin::FeeRate;
use spaces_protocol::slabel::SLabel;
use spaces_protocol::sname::SName;
use spaces_testutil::TestRig;
use spaces_wallet::Subject;
use spaces_wallet::export::WalletExport;
use subs_core::{HandleRequest, Operator};
use tempfile::TempDir;

const ALICE: &str = "wallet_99";
const BOB: &str = "wallet_98";
const FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(1);

// Finality threshold (blocks)
const FINALITY_BLOCKS: usize = 144;
// Permanence threshold (blocks) - finality + safety margin
const PERMANENCE_BLOCKS: usize = 288;

/// A single root cert scenario with its children.
#[derive(Serialize, Deserialize)]
pub struct RootCertScenario {
    pub name: String,
    pub description: String,
    /// Root certificate (space-level).
    #[serde(with = "cert_serde")]
    pub root_cert: Certificate,
    /// Leaf certificates under this root.
    pub leaves: Vec<LeafCertInfo>,
    /// Whether there's an on-chain commitment.
    pub has_commitment: bool,
    /// Whether the commitment is finalized (>= 144 blocks).
    pub is_finalized: bool,
    /// Whether the commitment is permanent (>= 288 blocks).
    pub is_permanent: bool,
}

#[derive(Serialize, Deserialize)]
pub struct LeafCertInfo {
    pub handle: String,
    #[serde(with = "cert_serde")]
    pub cert: Certificate,
    pub is_temporary: bool,
    pub has_exclusion_proof: bool,
    /// Expected sovereignty: "dependent", "pending", or "sovereign"
    pub expected_sovereignty: String,
}

/// Complete test vectors.
#[derive(Serialize, Deserialize)]
pub struct TestVectors {
    /// Trust anchors from spaced.
    pub anchors: Vec<RootAnchor>,
    /// Different root cert scenarios.
    pub scenarios: Vec<RootCertScenario>,
    /// Space name used for tests.
    pub space: String,
}

/// Borsh serde for Certificate.
mod cert_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(cert: &Certificate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = borsh::to_vec(cert).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Certificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        borsh::from_slice(&bytes).map_err(D::Error::custom)
    }
}

struct TestContext<'a> {
    rig: &'a TestRig,
    operator: Operator,
    space: SLabel,
    space_name: SLabel,
}

impl<'a> TestContext<'a> {
    async fn new(rig: &'a TestRig, temp_dir: &TempDir, space_index: usize) -> Self {
        let space_name = get_wallet_space(rig, ALICE, space_index).await;
        let space = SLabel::try_from(space_name.to_string().as_str()).expect("valid slabel");
        let operator = Operator::new(temp_dir.path().to_path_buf(), ALICE, rig.spaced.client.clone());
        Self { rig, operator, space, space_name }
    }

    async fn delegate(&self) {
        delegate_space(self.rig, ALICE, &self.space_name).await;
    }

    fn handle(&self, name: &str) -> String {
        format!("{}{}", name, self.space_name)
    }

    fn request(&self, name: &str, spk: &[u8]) -> HandleRequest {
        make_request(&self.handle(name), spk)
    }
}

async fn get_wallet_space(rig: &TestRig, wallet: &str, index: usize) -> SLabel {
    let spaces = rig.spaced.client.wallet_list_spaces(wallet).await
        .expect("wallet_list_spaces");
    let owned = spaces.owned.get(index)
        .unwrap_or_else(|| panic!("{} should own space at index {}", wallet, index));
    owned.spaceout.space.as_ref().expect("space").name.clone()
}

async fn delegate_space(rig: &TestRig, wallet: &str, space: &SLabel) {
    let res = wallet_send(rig, wallet, vec![
        RpcWalletRequest::Operate(OperateParams { subject: Subject::Label(space.clone()) })
    ]).await;
    check_wallet_response(&res);
    mine_and_sync(rig, 36).await;
}

async fn wallet_send(rig: &TestRig, wallet: &str, requests: Vec<RpcWalletRequest>) -> WalletResponse {
    rig.spaced.client.wallet_send_request(wallet, RpcWalletTxBuilder {
        bidouts: None,
        requests,
        fee_rate: Some(FEE_RATE),
        dust: None,
        force: false,
        confirmed_only: false,
        skip_tx_check: false,
    }).await.expect("wallet_send_request")
}

fn check_wallet_response(res: &WalletResponse) {
    for tx in &res.result {
        if let Some(e) = &tx.error {
            let msg = e.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(", ");
            panic!("wallet error: {}", msg);
        }
    }
}

async fn load_wallet(rig: &TestRig, wallets_dir: PathBuf, name: &str) {
    let json = std::fs::read_to_string(wallets_dir.join(format!("{name}.json")))
        .expect("read wallet file");
    let export = WalletExport::from_str(&json).expect("parse wallet");
    rig.spaced.client.wallet_import(export).await.expect("wallet_import");
}

async fn sync_all(rig: &TestRig) {
    rig.wait_until_synced().await.expect("wait_until_synced");
    rig.wait_until_wallet_synced(ALICE).await.expect("sync alice");
    rig.wait_until_wallet_synced(BOB).await.expect("sync bob");
}

async fn mine_and_sync(rig: &TestRig, blocks: usize) {
    rig.mine_blocks(blocks, None).await.expect("mine_blocks");
    sync_all(rig).await;
}

fn make_request(handle: &str, spk: &[u8]) -> HandleRequest {
    HandleRequest {
        handle: test_sname(handle),
        script_pubkey: hex::encode(spk),
        dev_private_key: None,
    }
}

fn test_sname(s: &str) -> SName {
    SName::try_from(s).expect("valid sname")
}

async fn generate_vectors(rig: &TestRig, temp_dir: &TempDir) -> TestVectors {
    sync_all(rig).await;
    let ctx = TestContext::new(rig, temp_dir, 0).await;
    ctx.delegate().await;

    let mut scenarios = Vec::new();

    // Scenario 1: Root cert WITHOUT commitment (no on-chain commitment yet)
    // Children are temporary with dependent state
    println!("Generating scenario 1: No commitment (dependent)...");

    ctx.operator.add_requests(vec![
        ctx.request("alice", &[0x01; 33]),
        ctx.request("bob", &[0x02; 33]),
    ]).await.expect("add_requests");

    // Issue certs BEFORE any commit - these are temporary with no exclusion proof
    let handle_a = test_sname(&ctx.handle("alice"));
    let (root_no_commit, leaf_a) = ctx.operator.issue_cert(&handle_a).await.expect("issue cert");
    let leaf_a = leaf_a.expect("leaf cert");

    let handle_b = test_sname(&ctx.handle("bob"));
    let (_, leaf_b) = ctx.operator.issue_cert(&handle_b).await.expect("issue cert");
    let leaf_b = leaf_b.expect("leaf cert");

    scenarios.push(RootCertScenario {
        name: "no_commitment".to_string(),
        description: "Root cert without on-chain commitment. Children are temporary (dependent).".to_string(),
        root_cert: root_no_commit,
        leaves: vec![
            LeafCertInfo {
                handle: ctx.handle("alice"),
                cert: leaf_a,
                is_temporary: true,
                has_exclusion_proof: false,
                expected_sovereignty: "dependent".to_string(),
            },
            LeafCertInfo {
                handle: ctx.handle("bob"),
                cert: leaf_b,
                is_temporary: true,
                has_exclusion_proof: false,
                expected_sovereignty: "dependent".to_string(),
            },
        ],
        has_commitment: false,
        is_finalized: false,
        is_permanent: false,
    });

    // Scenario 2: Root cert WITH commitment but NOT finalized (< 144 blocks)
    // Children have pending sovereignty state
    println!("Generating scenario 2: Commitment pending (< 144 blocks)...");

    // Commit locally and on-chain
    ctx.operator.commit_local(&ctx.space).await.expect("commit_local");
    ctx.operator.commit(&ctx.space, Some(FEE_RATE)).await.expect("commit");

    // Mine just a few blocks - NOT enough for finality
    mine_and_sync(rig, 36).await;

    // Issue certs - these should have pending sovereignty
    let (root_pending, leaf_pending_a) = ctx.operator.issue_cert(&handle_a).await.expect("issue cert");
    let leaf_pending_a = leaf_pending_a.expect("leaf cert");

    let (_, leaf_pending_b) = ctx.operator.issue_cert(&handle_b).await.expect("issue cert");
    let leaf_pending_b = leaf_pending_b.expect("leaf cert");

    // Also add a NEW staged handle to get temporary cert WITH exclusion proof
    ctx.operator.add_requests(vec![
        ctx.request("carol", &[0x10; 33]),
    ]).await.expect("add staged request");

    let staged_handle = test_sname(&ctx.handle("carol"));
    let (_, staged_leaf) = ctx.operator.issue_cert(&staged_handle).await.expect("issue staged cert");
    let staged_leaf = staged_leaf.expect("staged leaf cert");

    scenarios.push(RootCertScenario {
        name: "commitment_pending".to_string(),
        description: "Root cert with commitment, not yet finalized (< 144 blocks). Pending sovereignty.".to_string(),
        root_cert: root_pending,
        leaves: vec![
            LeafCertInfo {
                handle: ctx.handle("alice"),
                cert: leaf_pending_a,
                is_temporary: false,
                has_exclusion_proof: false,
                expected_sovereignty: "pending".to_string(), // committed, not finalized
            },
            LeafCertInfo {
                handle: ctx.handle("bob"),
                cert: leaf_pending_b,
                is_temporary: false,
                has_exclusion_proof: false,
                expected_sovereignty: "pending".to_string(), // committed, not finalized
            },
            LeafCertInfo {
                handle: ctx.handle("carol"),
                cert: staged_leaf,
                is_temporary: true,
                has_exclusion_proof: true,
                expected_sovereignty: "dependent".to_string(), // staged, not committed
            },
        ],
        has_commitment: true,
        is_finalized: false,
        is_permanent: false,
    });

    // Scenario 3: Root cert WITH commitment, finalized but NOT permanent
    // (>= 144 blocks but < 288 blocks)
    // Children have sovereign state but not permanent
    println!("Generating scenario 3: Commitment finalized, not permanent (144-288 blocks)...");

    // Mine to reach finality but not permanence
    // We've mined 10, need to reach 144+
    mine_and_sync(rig, FINALITY_BLOCKS - 10 + 5).await; // ~149 blocks total

    // Issue certs - these should have sovereign state
    let (root_finalized, leaf_sov_a) = ctx.operator.issue_cert(&handle_a).await.expect("issue cert");
    let leaf_sov_a = leaf_sov_a.expect("leaf cert");

    let (_, leaf_sov_b) = ctx.operator.issue_cert(&handle_b).await.expect("issue cert");
    let leaf_sov_b = leaf_sov_b.expect("leaf cert");

    // Stage another handle for temporary cert with exclusion
    ctx.operator.add_requests(vec![
        ctx.request("dave", &[0x20; 33]),
    ]).await.expect("add staged request");

    let staged_fin_handle = test_sname(&ctx.handle("dave"));
    let (_, staged_fin_leaf) = ctx.operator.issue_cert(&staged_fin_handle).await.expect("issue staged cert");
    let staged_fin_leaf = staged_fin_leaf.expect("staged leaf cert");

    scenarios.push(RootCertScenario {
        name: "commitment_finalized".to_string(),
        description: "Root cert with finalized commitment (>= 144 blocks), not permanent. Sovereign state.".to_string(),
        root_cert: root_finalized,
        leaves: vec![
            LeafCertInfo {
                handle: ctx.handle("alice"),
                cert: leaf_sov_a,
                is_temporary: false,
                has_exclusion_proof: false,
                expected_sovereignty: "sovereign".to_string(), // committed, finalized
            },
            LeafCertInfo {
                handle: ctx.handle("bob"),
                cert: leaf_sov_b,
                is_temporary: false,
                has_exclusion_proof: false,
                expected_sovereignty: "sovereign".to_string(), // committed, finalized
            },
            LeafCertInfo {
                handle: ctx.handle("dave"),
                cert: staged_fin_leaf,
                is_temporary: true,
                has_exclusion_proof: true,
                expected_sovereignty: "dependent".to_string(), // staged, not committed
            },
        ],
        has_commitment: true,
        is_finalized: true,
        is_permanent: false,
    });

    // Scenario 4: Root cert WITH commitment, finalized AND permanent
    // (>= 288 blocks)
    // Children have sovereign state and are permanent
    println!("Generating scenario 4: Commitment permanent (>= 288 blocks)...");

    // Mine to reach permanence
    // We've mined ~149 blocks, need to reach 288+
    mine_and_sync(rig, PERMANENCE_BLOCKS - FINALITY_BLOCKS - 5 + 10).await; // ~298 blocks total

    // Issue certs - these should be sovereign AND permanent
    let (root_permanent, leaf_perm_a) = ctx.operator.issue_cert(&handle_a).await.expect("issue cert");
    let leaf_perm_a = leaf_perm_a.expect("leaf cert");

    let (_, leaf_perm_b) = ctx.operator.issue_cert(&handle_b).await.expect("issue cert");
    let leaf_perm_b = leaf_perm_b.expect("leaf cert");

    // Stage another handle for temporary cert with exclusion
    ctx.operator.add_requests(vec![
        ctx.request("eve", &[0x30; 33]),
    ]).await.expect("add staged request");

    let staged_perm_handle = test_sname(&ctx.handle("eve"));
    let (_, staged_perm_leaf) = ctx.operator.issue_cert(&staged_perm_handle).await.expect("issue staged cert");
    let staged_perm_leaf = staged_perm_leaf.expect("staged leaf cert");

    scenarios.push(RootCertScenario {
        name: "commitment_permanent".to_string(),
        description: "Root cert with permanent commitment (>= 288 blocks). Sovereign and permanent.".to_string(),
        root_cert: root_permanent,
        leaves: vec![
            LeafCertInfo {
                handle: ctx.handle("alice"),
                cert: leaf_perm_a,
                is_temporary: false,
                has_exclusion_proof: false,
                expected_sovereignty: "sovereign".to_string(), // committed, permanent
            },
            LeafCertInfo {
                handle: ctx.handle("bob"),
                cert: leaf_perm_b,
                is_temporary: false,
                has_exclusion_proof: false,
                expected_sovereignty: "sovereign".to_string(), // committed, permanent
            },
            LeafCertInfo {
                handle: ctx.handle("eve"),
                cert: staged_perm_leaf,
                is_temporary: true,
                has_exclusion_proof: true,
                expected_sovereignty: "dependent".to_string(), // staged, not committed
            },
        ],
        has_commitment: true,
        is_finalized: true,
        is_permanent: true,
    });

    // Scenario 5: Temporary certs at the CURRENT TIP (should verify!)
    // No more mining after this - these temp certs are valid with final anchors
    println!("Generating scenario 5: Temporary certs at current tip...");

    // Stage new handles at the current tip (after all mining is done)
    ctx.operator.add_requests(vec![
        ctx.request("tip1", &[0x40; 33]),
        ctx.request("tip2", &[0x41; 33]),
    ]).await.expect("add tip requests");

    let tip1_handle = test_sname(&ctx.handle("tip1"));
    let tip2_handle = test_sname(&ctx.handle("tip2"));

    let (root_tip, tip1_leaf) = ctx.operator.issue_cert(&tip1_handle).await.expect("issue tip1 cert");
    let tip1_leaf = tip1_leaf.expect("tip1 leaf cert");

    let (_, tip2_leaf) = ctx.operator.issue_cert(&tip2_handle).await.expect("issue tip2 cert");
    let tip2_leaf = tip2_leaf.expect("tip2 leaf cert");

    scenarios.push(RootCertScenario {
        name: "temp_at_tip".to_string(),
        description: "Temporary certs issued at the current chain tip. Should verify with final anchors.".to_string(),
        root_cert: root_tip,
        leaves: vec![
            LeafCertInfo {
                handle: ctx.handle("tip1"),
                cert: tip1_leaf,
                is_temporary: true,
                has_exclusion_proof: true,
                expected_sovereignty: "dependent".to_string(),
            },
            LeafCertInfo {
                handle: ctx.handle("tip2"),
                cert: tip2_leaf,
                is_temporary: true,
                has_exclusion_proof: true,
                expected_sovereignty: "dependent".to_string(),
            },
        ],
        has_commitment: true, // Parent has commitment
        is_finalized: true,
        is_permanent: true,
    });

    // Get trust anchors AFTER all cert issuance (these match the tip)
    println!("Fetching trust anchors...");
    let rpc_anchors = rig.spaced.client.get_root_anchors().await.expect("get_root_anchors");
    let json = serde_json::to_string(&rpc_anchors).expect("serialize anchors");
    let anchors: Vec<RootAnchor> = serde_json::from_str(&json).expect("parse anchors");

    TestVectors {
        anchors,
        scenarios,
        space: ctx.space_name.to_string(),
    }
}

fn save_vectors(vectors: &TestVectors, output_dir: &PathBuf) {
    std::fs::create_dir_all(output_dir).expect("create fixtures dir");

    // Save anchors as JSON
    let anchors_path = output_dir.join("anchors.json");
    let anchors_json = serde_json::to_string_pretty(&vectors.anchors).expect("serialize anchors");
    std::fs::write(&anchors_path, &anchors_json).expect("write anchors.json");
    println!("Wrote anchors to: {}", anchors_path.display());

    // Save each scenario
    for scenario in &vectors.scenarios {
        let scenario_dir = output_dir.join(&scenario.name);
        std::fs::create_dir_all(&scenario_dir).expect("create scenario dir");

        // Root cert
        let root_path = scenario_dir.join("root_cert.borsh");
        let root_bytes = borsh::to_vec(&scenario.root_cert).expect("serialize root cert");
        std::fs::write(&root_path, &root_bytes).expect("write root cert");
        println!("  {} root cert: {}", scenario.name, root_path.display());

        // Leaf certs
        for leaf in &scenario.leaves {
            let leaf_name = leaf.handle.split('@').next().unwrap_or(&leaf.handle);
            let leaf_path = scenario_dir.join(format!("{}.borsh", leaf_name));
            let leaf_bytes = borsh::to_vec(&leaf.cert).expect("serialize leaf cert");
            std::fs::write(&leaf_path, &leaf_bytes).expect("write leaf cert");
        }

        // Scenario metadata
        let meta_path = scenario_dir.join("metadata.json");
        let meta = serde_json::json!({
            "name": scenario.name,
            "description": scenario.description,
            "has_commitment": scenario.has_commitment,
            "is_finalized": scenario.is_finalized,
            "is_permanent": scenario.is_permanent,
            "leaves": scenario.leaves.iter().map(|l| serde_json::json!({
                "handle": l.handle,
                "is_temporary": l.is_temporary,
                "has_exclusion_proof": l.has_exclusion_proof,
                "expected_sovereignty": l.expected_sovereignty,
            })).collect::<Vec<_>>(),
        });
        let meta_json = serde_json::to_string_pretty(&meta).expect("serialize metadata");
        std::fs::write(&meta_path, &meta_json).expect("write metadata");
    }

    // Save complete vectors as single JSON
    let vectors_path = output_dir.join("test_vectors.json");
    let vectors_json = serde_json::to_string_pretty(&vectors).expect("serialize vectors");
    std::fs::write(&vectors_path, &vectors_json).expect("write test_vectors.json");
    println!("Wrote complete vectors to: {}", vectors_path.display());

    // Summary
    println!("\n=== Test Vector Summary ===");
    println!("Space: {}", vectors.space);
    println!("Anchors: {}", vectors.anchors.len());
    println!("Scenarios: {}", vectors.scenarios.len());
    for scenario in &vectors.scenarios {
        println!("  - {}: {} leaves", scenario.name, scenario.leaves.len());
    }
}

#[tokio::test]
async fn generate_test_vectors() {
    let rig = TestRig::new_with_regtest_preset().await.expect("TestRig::new");
    let wallets_path = rig.testdata_wallets_path().await;

    let count = rig.get_block_count().await.expect("get_block_count");
    assert!(count > 3000, "expected initialized test set");

    rig.wait_until_synced().await.expect("wait_until_synced");
    load_wallet(&rig, wallets_path.clone(), ALICE).await;
    load_wallet(&rig, wallets_path, BOB).await;

    let temp_dir = TempDir::new().expect("TempDir");
    let vectors = generate_vectors(&rig, &temp_dir).await;

    // Output directory for test vectors
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("certrelay")
        .join("tests")
        .join("fixtures");

    save_vectors(&vectors, &output_dir);

    println!("\nTest vectors generated successfully!");
}
