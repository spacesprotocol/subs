//! Integration tests for the subs Operator API.
//!
//! These tests exercise the Operator workflow: add → commit → prove.
//! Tests use only the Operator interface without accessing LocalSpace internals.

use spaces_protocol::sname::SName;
use spaces_protocol::slabel::SLabel;
use subs_core::{HandleRequest, Operator};
use tempfile::TempDir;

fn make_request(handle: &str, spk: &[u8]) -> HandleRequest {
    HandleRequest {
        handle: SName::try_from(handle).unwrap(),
        script_pubkey: hex::encode(spk),
        dev_private_key: None,
    }
}

fn test_space() -> SLabel {
    SLabel::try_from("@testspace").unwrap()
}

#[tokio::test]
async fn test_add_commit_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let operator = Operator::offline(temp_dir.path().to_path_buf());
    let space = test_space();

    // Add requests
    let requests = vec![
        make_request("alice@testspace", &[0x01; 33]),
        make_request("bob@testspace", &[0x02; 33]),
        make_request("charlie@testspace", &[0x03; 33]),
    ];

    let add_result = operator.add_requests(requests).await.unwrap();
    assert_eq!(add_result.total_added, 3);
    assert_eq!(add_result.by_space.len(), 1);
    assert_eq!(add_result.by_space[0].space, space);

    // Check status shows staged handles
    let status = operator.status().await.unwrap();
    assert_eq!(status.spaces.len(), 1);
    assert_eq!(status.spaces[0].staged_handles, 3);
    assert_eq!(status.spaces[0].commitments, 0);

    // Commit
    let commit = operator.commit_local(&space).await.unwrap();
    assert!(commit.is_initial);
    assert_eq!(commit.handles_committed, 3);
    assert!(!commit.root.is_empty());
    assert!(commit.prev_root.is_none());

    // Check status after commit
    let status = operator.status().await.unwrap();
    assert_eq!(status.spaces[0].staged_handles, 0);
    assert_eq!(status.spaces[0].commitments, 1);
}

#[tokio::test]
async fn test_multiple_commits() {
    let temp_dir = TempDir::new().unwrap();
    let operator = Operator::offline(temp_dir.path().to_path_buf());
    let space = test_space();

    // First batch
    operator.add_requests(vec![
        make_request("alice@testspace", &[0x01; 33]),
        make_request("bob@testspace", &[0x02; 33]),
    ]).await.unwrap();

    let commit1 = operator.commit_local(&space).await.unwrap();
    assert!(commit1.is_initial);
    let root1 = commit1.root.clone();

    // Second batch
    operator.add_requests(vec![
        make_request("charlie@testspace", &[0x03; 33]),
        make_request("dave@testspace", &[0x04; 33]),
    ]).await.unwrap();

    let commit2 = operator.commit_local(&space).await.unwrap();
    assert!(!commit2.is_initial);
    assert_eq!(commit2.prev_root.as_ref(), Some(&root1));
    assert_ne!(commit2.root, root1);

    // Status should show 2 commits
    let status = operator.status().await.unwrap();
    assert_eq!(status.spaces[0].commitments, 2);
}

#[tokio::test]
async fn test_duplicate_detection() {
    let temp_dir = TempDir::new().unwrap();
    let operator = Operator::offline(temp_dir.path().to_path_buf());
    let space = test_space();

    // Add and commit alice
    operator.add_requests(vec![make_request("alice@testspace", &[0x01; 33])])
        .await.unwrap();
    operator.commit_local(&space).await.unwrap();

    // Try to add alice again with same spk - should be skipped
    let result = operator.add_requests(vec![make_request("alice@testspace", &[0x01; 33])])
        .await.unwrap();
    assert_eq!(result.total_added, 0);
    assert_eq!(result.by_space[0].skipped.len(), 1);
    assert!(matches!(
        result.by_space[0].skipped[0].reason,
        subs_core::SkipReason::AlreadyCommitted
    ));

    // Try to add alice with different spk - should be skipped
    let result = operator.add_requests(vec![make_request("alice@testspace", &[0x02; 33])])
        .await.unwrap();
    assert_eq!(result.total_added, 0);
    assert!(matches!(
        result.by_space[0].skipped[0].reason,
        subs_core::SkipReason::AlreadyCommittedDifferentSpk
    ));
}

#[tokio::test]
async fn test_multi_space() {
    let temp_dir = TempDir::new().unwrap();
    let operator = Operator::offline(temp_dir.path().to_path_buf());

    let space1 = SLabel::try_from("@space1").unwrap();
    let space2 = SLabel::try_from("@space2").unwrap();

    // Add requests to multiple spaces
    let add_result = operator.add_requests(vec![
        make_request("alice@space1", &[0x01; 33]),
        make_request("bob@space1", &[0x02; 33]),
        make_request("charlie@space2", &[0x03; 33]),
    ]).await.unwrap();
    assert_eq!(add_result.total_added, 3);
    assert_eq!(add_result.by_space.len(), 2);

    // Commit each space
    let commit1 = operator.commit_local(&space1).await.unwrap();
    let commit2 = operator.commit_local(&space2).await.unwrap();
    assert_eq!(commit1.handles_committed, 2);
    assert_eq!(commit2.handles_committed, 1);

    // Status should show both spaces
    let status = operator.status().await.unwrap();
    assert_eq!(status.spaces.len(), 2);
}

#[tokio::test]
async fn test_commit_requires_staged() {
    let temp_dir = TempDir::new().unwrap();
    let operator = Operator::offline(temp_dir.path().to_path_buf());
    let space = test_space();

    // Create the space first
    operator.load_or_create_space(&space).await.unwrap();

    // Can't commit without staged entries
    let result = operator.commit_local(&space).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_empty_requests_error() {
    let temp_dir = TempDir::new().unwrap();
    let operator = Operator::offline(temp_dir.path().to_path_buf());

    let result = operator.add_requests(vec![]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_list_spaces_from_disk() {
    let temp_dir = TempDir::new().unwrap();
    let operator = Operator::offline(temp_dir.path().to_path_buf());

    // Initially empty
    let spaces = operator.list_spaces_from_disk().unwrap();
    assert!(spaces.is_empty());

    // Create a space by adding requests
    operator.add_requests(vec![make_request("alice@testspace", &[0x01; 33])])
        .await.unwrap();

    // Should now find the space
    let spaces = operator.list_spaces_from_disk().unwrap();
    assert_eq!(spaces.len(), 1);
}
