//! Full end-to-end tests combining off-chain subs operations with on-chain commitments.

use std::path::PathBuf;
use std::str::FromStr;

use libveritas::cert::Witness;
use spaces_client::rpc::{OperateParams, RpcClient, RpcWalletRequest, RpcWalletTxBuilder};
use spaces_client::wallets::WalletResponse;
use spaces_protocol::bitcoin::FeeRate;
use spaces_protocol::slabel::SLabel;
use spaces_protocol::sname::SName;
use spaces_testutil::TestRig;
use spaces_wallet::Subject;
use spaces_wallet::export::WalletExport;
use subs_core::{HandleRequest, Operator};
use subs_prover::Prover;
use tempfile::TempDir;

const ALICE: &str = "wallet_99";
const BOB: &str = "wallet_98";
const FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(1);

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

fn assert_temp_cert(cert: &libveritas::cert::Certificate, expect_exclusion: bool) {
    assert!(cert.is_temporary(), "expected temporary certificate");
    let has_exclusion = match &cert.witness {
        Witness::Leaf { handles, signature: Some(_), .. } => !handles.0.is_empty(),
        _ => false,
    };
    assert_eq!(has_exclusion, expect_exclusion, "exclusion proof mismatch");
}

fn assert_final_cert(cert: &libveritas::cert::Certificate) {
    assert!(cert.is_final(), "expected final certificate");
}

async fn test_certificate_flow(rig: &TestRig, temp_dir: &TempDir) {
    sync_all(rig).await;
    let ctx = TestContext::new(rig, temp_dir, 0).await;
    ctx.delegate().await;

    // Stage handles
    ctx.operator.add_requests(vec![
        ctx.request("alice", &[0x01; 33]),
        ctx.request("bob", &[0x02; 33]),
    ]).await.expect("add_requests");

    // Temporary certificate (no prior commits, no exclusion proof)
    let handle = test_sname(&ctx.handle("alice"));
    let (_root_cert, handle_cert) = ctx.operator.issue_cert(&handle).await.expect("issue_cert");
    let handle_cert = handle_cert.expect("handle cert");
    assert_temp_cert(&handle_cert, false);

    // Commit locally then on-chain
    ctx.operator.commit_local(&ctx.space).await.expect("commit_local");
    ctx.operator.commit(&ctx.space, Some(FEE_RATE)).await.expect("commit");
    mine_and_sync(rig, 200).await;

    // Final certificate (handle now committed)
    let (_root_cert, handle_cert) = ctx.operator.issue_cert(&handle).await.expect("issue_cert");
    let handle_cert = handle_cert.expect("handle cert");
    assert_final_cert(&handle_cert);

    // Temporary certificate with exclusion proof (prior commit exists)
    ctx.operator.add_requests(vec![ctx.request("staged", &[0x99; 33])]).await
        .expect("add_requests");
    let staged_handle = test_sname(&ctx.handle("staged"));
    let (_root_cert, handle_cert) = ctx.operator.issue_cert(&staged_handle).await
        .expect("issue_cert");
    let handle_cert = handle_cert.expect("handle cert");
    assert_temp_cert(&handle_cert, true);
}

async fn test_commitment_chain(rig: &TestRig, temp_dir: &TempDir) {
    sync_all(rig).await;
    let ctx = TestContext::new(rig, temp_dir, 1).await;
    ctx.delegate().await;

    // First commit (initial - no proving required)
    ctx.operator.add_requests(vec![
        ctx.request("user1", &[0x11; 33]),
        ctx.request("user2", &[0x12; 33]),
    ]).await.expect("add_requests");
    let commit1 = ctx.operator.commit_local(&ctx.space).await.expect("commit_local");
    assert!(commit1.is_initial);

    ctx.operator.commit(&ctx.space, Some(FEE_RATE)).await.expect("commit");
    mine_and_sync(rig, 200).await;

    // Second commit (should chain from first)
    ctx.operator.add_requests(vec![
        ctx.request("user3", &[0x13; 33]),
        ctx.request("user4", &[0x14; 33]),
    ]).await.expect("add_requests");
    let commit2 = ctx.operator.commit_local(&ctx.space).await.expect("commit_local");
    assert!(!commit2.is_initial);
    assert_eq!(commit2.prev_root.as_ref(), Some(&commit1.root));

    // Prove all pending requests before on-chain commit
    let prover = Prover::new();
    while let Some(request) = ctx.operator.get_next_proving_request(&ctx.space).await
        .expect("get_next_proving_request")
    {
        let receipt = prover.prove(&request).expect("prove");
        ctx.operator.fulfill_request(&ctx.space, &request, &receipt).await
            .expect("fulfill_request");
    }

    ctx.operator.commit(&ctx.space, Some(FEE_RATE)).await.expect("commit");
    mine_and_sync(rig, 200).await;

    // Verify chain on-chain
    let tip = rig.spaced.client.get_commitment(Subject::Label(ctx.space_name.clone()), None).await
        .expect("get_commitment")
        .expect("commitment should exist");

    let mut root1 = [0u8; 32];
    let mut root2 = [0u8; 32];
    hex::decode_to_slice(&commit1.root, &mut root1).expect("decode root1");
    hex::decode_to_slice(&commit2.root, &mut root2).expect("decode root2");

    assert_eq!(tip.state_root, root2);
    assert_eq!(tip.prev_root, Some(root1));

    // Issue final certs for handles from both commits to confirm they
    // work after proving and across multiple commits.
    let handle1 = test_sname(&ctx.handle("user1"));
    let (_root_cert, handle_cert) = ctx.operator.issue_cert(&handle1).await.expect("issue_cert user1");
    assert_final_cert(&handle_cert.expect("handle cert"));

    let handle3 = test_sname(&ctx.handle("user3"));
    let (_root_cert, handle_cert) = ctx.operator.issue_cert(&handle3).await.expect("issue_cert user3");
    assert_final_cert(&handle_cert.expect("handle cert"));

    // Verify status
    let status = ctx.operator.status().await.expect("status");
    let space_status = status.spaces.iter()
        .find(|s| s.space == ctx.space)
        .expect("space in status");
    assert_eq!(space_status.commitments, 2);
}

#[tokio::test]
async fn run_full_e2e_tests() {
    let rig = TestRig::new_with_regtest_preset().await.expect("TestRig::new");
    let wallets_path = rig.testdata_wallets_path().await;

    let count = rig.get_block_count().await.expect("get_block_count");
    assert!(count > 3000, "expected initialized test set");

    rig.wait_until_synced().await.expect("wait_until_synced");
    load_wallet(&rig, wallets_path.clone(), ALICE).await;
    load_wallet(&rig, wallets_path, BOB).await;

    let temp_dir1 = TempDir::new().expect("TempDir");
    let temp_dir2 = TempDir::new().expect("TempDir");

    test_certificate_flow(&rig, &temp_dir1).await;
    test_commitment_chain(&rig, &temp_dir2).await;
}
