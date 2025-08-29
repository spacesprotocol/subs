use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use spacedb::{Hash, Sha256Hasher, subtree::{SubTree, ValueOrHash}, VerifyError};
use crate::{BatchReader};


#[derive(Serialize, Deserialize, Clone)]
pub struct Commitment {
    pub space: Hash,
    pub policy_step: [u32; 8],
    pub policy_fold: [u32; 8],
    pub initial_root: Hash,
    pub final_root: Hash,
    pub transcript: Hash,
    pub kind: CommitmentKind,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum CommitmentKind {
    Fold,
    Step,
}

#[derive(Debug)]
pub enum GuestError {
    KeyExists,
    IncompleteSubTree,
}

pub type Result<T> = core::result::Result<T, GuestError>;

pub fn run(subtree: Vec<u8>, input: Vec<u8>, policy_step: [u32; 8], policy_fold: [u32; 8]) -> Result<Commitment> {
    let config = bincode::config::standard();
    let (mut subtree, _): (SubTree<Sha256Hasher>, usize) =
        bincode::decode_from_slice(&subtree, config).expect("decoding subtree error");

    let initial_root = subtree.compute_root().unwrap();
    let reader = BatchReader(&input);

    for entry in reader.iter() {
        subtree.insert(
            entry.handle.try_into().expect("32 byte subspace hash slice"),
            ValueOrHash::Hash(entry.script_pubkey.try_into().expect("32 byte script_pubkey hash slice")),
        )
            .map_err(|e| match e {
                spacedb::Error::Verify(e) => {
                    match e {
                        VerifyError::IncompleteProof => GuestError::IncompleteSubTree,
                        VerifyError::KeyNotFound => GuestError::IncompleteSubTree,
                        VerifyError::KeyExists => GuestError::KeyExists,
                    }
                }
                _ => {
                    unreachable!("expected verify error")
                }
            })?;
    }

    let final_root = subtree.compute_root().unwrap();

    Ok(Commitment {
        space: reader.space_hash().try_into().expect("space hash error"),
        initial_root,
        final_root,
        transcript: final_root,
        policy_step,
        policy_fold,
        kind: CommitmentKind::Step,
    })
}

impl core::fmt::Display for GuestError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            GuestError::KeyExists => write!(f, "Cannot register a subspace that already exists"),
            GuestError::IncompleteSubTree => write!(f, "SubTree is incomplete"),
        }
    }
}
