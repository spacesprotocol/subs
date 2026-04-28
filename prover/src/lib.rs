//! ZK prover library for subs.
//!
//! Provides the `Prover` struct for generating STARK proofs and SNARK compression.

pub mod server;

use std::time::Instant;

use anyhow::{anyhow, Result};
use libveritas::constants::{FOLD_ELF, FOLD_ID, STEP_ELF, STEP_ID};
use libveritas_zk::guest::Commitment;
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, Receipt};
use spacedb::{NodeHasher, Sha256Hasher};
use spacedb::subtree::{ProofType, SubTree, ValueOrHash};
use subs_types::{CalibrationInfo, CompressInput, EstimateResult, ProvingRequest, SegmentEstimate};

/// Build a synthetic ProvingRequest::Step for benchmarking/calibration.
///
/// Creates a tree with `existing` handles, then generates an exclusion proof
/// for `insert` new handles and returns the corresponding ProvingRequest.
pub fn build_bench_request(existing: usize, insert: usize) -> Result<ProvingRequest> {
    let mut tree: SubTree<Sha256Hasher> = SubTree::empty();

    for i in 0..existing {
        let key = Sha256Hasher::hash(format!("existing-{}", i).as_bytes());
        let value = Sha256Hasher::hash(format!("value-{}", i).as_bytes());
        let mut val = Vec::with_capacity(64);
        val.extend_from_slice(&key);
        val.extend_from_slice(&value);
        tree.insert(key, ValueOrHash::Value(val))
            .map_err(|e| anyhow!("insert existing: {:?}", e))?;
    }

    let mut new_keys = Vec::with_capacity(insert);
    for i in 0..insert {
        new_keys.push(Sha256Hasher::hash(format!("new-{}", i).as_bytes()));
    }

    let proof = tree
        .prove(&new_keys, ProofType::Standard)
        .map_err(|e| anyhow!("prove: {:?}", e))?;
    let exclusion_proof = proof.to_vec()
        .map_err(|e| anyhow!("serialize proof: {:?}", e))?;

    let mut zk_batch = Vec::with_capacity(32 + insert * 64);
    for key in &new_keys {
        zk_batch.extend_from_slice(key);
        zk_batch.extend_from_slice(&[0u8; 32]); // script pubkey hash
    }

    Ok(ProvingRequest::Step {
        commitment_id: 0,
        idx: 1,
        prev_root: None,
        root: String::new(),
        exclusion_proof,
        zk_batch,
    })
}

/// External prover for generating ZK proofs.
///
/// Handles both Step and Fold proving requests. Use this with
/// `Operator::get_next_proving_request()` and `Operator::fulfill_request()`.
///
/// # Example
/// ```ignore
/// use subs_prover::Prover;
///
/// let prover = Prover::new();
/// while let Some(request) = operator.get_next_proving_request(&space).await? {
///     let receipt = prover.prove(&request)?;
///     operator.fulfill_request(&space, &request, &receipt).await?;
/// }
/// ```
pub struct Prover;

impl Prover {
    pub fn new() -> Self {
        Self
    }

    /// Prove a ProvingRequest and return the serialized receipt.
    pub fn prove(&self, request: &ProvingRequest) -> Result<Vec<u8>> {
        match request {
            ProvingRequest::Step {
                idx,
                exclusion_proof,
                zk_batch,
                ..
            } => self.prove_step(*idx, exclusion_proof, zk_batch),
            ProvingRequest::Fold {
                idx,
                acc_receipt,
                acc_commitment,
                step_receipt,
                step_commitment,
                ..
            } => self.prove_fold(
                *idx,
                acc_receipt,
                acc_commitment,
                step_receipt,
                step_commitment,
            ),
        }
    }

    fn prove_step(&self, idx: usize, exclusion_proof: &[u8], zk_batch: &[u8]) -> Result<Vec<u8>> {
        let env = ExecutorEnv::builder()
            .write(&(
                exclusion_proof.to_vec(),
                zk_batch.to_vec(),
                STEP_ID,
                FOLD_ID,
            ))
            .map_err(|e| anyhow!("[#{}] env write: {}", idx, e))?
            .build()
            .map_err(|e| anyhow!("[#{}] env build: {}", idx, e))?;

        let prove_info = default_prover()
            .prove_with_opts(env, STEP_ELF, &ProverOpts::succinct())
            .map_err(|e| anyhow!("[#{}] prove step failed: {}", idx, e))?;

        let receipt_bytes = borsh::to_vec(&prove_info.receipt)
            .map_err(|e| anyhow!("[#{}] serialize receipt: {}", idx, e))?;

        Ok(receipt_bytes)
    }

    fn prove_fold(
        &self,
        idx: usize,
        acc_receipt: &[u8],
        acc_commitment: &Commitment,
        step_receipt: &[u8],
        step_commitment: &Commitment,
    ) -> Result<Vec<u8>> {
        let acc: Receipt = borsh::from_slice(acc_receipt)
            .map_err(|e| anyhow!("deserialize acc receipt: {}", e))?;
        let step: Receipt = borsh::from_slice(step_receipt)
            .map_err(|e| anyhow!("deserialize step receipt: {}", e))?;

        let env = ExecutorEnv::builder()
            .add_assumption(acc)
            .add_assumption(step)
            .write(&(acc_commitment.clone(), step_commitment.clone()))
            .map_err(|e| anyhow!("[#{}] env write: {}", idx, e))?
            .build()
            .map_err(|e| anyhow!("[#{}] env build: {}", idx, e))?;

        let prove_info = default_prover()
            .prove_with_opts(env, FOLD_ELF, &ProverOpts::succinct())
            .map_err(|e| anyhow!("[#{}] fold prove failed: {}", idx, e))?;

        let receipt_bytes = borsh::to_vec(&prove_info.receipt)
            .map_err(|e| anyhow!("[#{}] serialize receipt: {}", idx, e))?;

        Ok(receipt_bytes)
    }

    /// Execute a proving request without generating a proof.
    /// Returns cycle counts and an optional time estimate.
    pub fn estimate(
        &self,
        request: &ProvingRequest,
        calibration: Option<&CalibrationInfo>,
    ) -> Result<EstimateResult> {
        let (elf, env) = match request {
            ProvingRequest::Step {
                idx,
                exclusion_proof,
                zk_batch,
                ..
            } => {
                let env = ExecutorEnv::builder()
                    .write(&(
                        exclusion_proof.to_vec(),
                        zk_batch.to_vec(),
                        STEP_ID,
                        FOLD_ID,
                    ))
                    .map_err(|e| anyhow!("[#{}] env write: {}", idx, e))?
                    .build()
                    .map_err(|e| anyhow!("[#{}] env build: {}", idx, e))?;
                (STEP_ELF, env)
            }
            ProvingRequest::Fold {
                idx,
                acc_receipt,
                acc_commitment,
                step_receipt,
                step_commitment,
                ..
            } => {
                let acc: Receipt = borsh::from_slice(acc_receipt)
                    .map_err(|e| anyhow!("deserialize acc receipt: {}", e))?;
                let step: Receipt = borsh::from_slice(step_receipt)
                    .map_err(|e| anyhow!("deserialize step receipt: {}", e))?;

                let env = ExecutorEnv::builder()
                    .add_assumption(acc)
                    .add_assumption(step)
                    .write(&(acc_commitment.clone(), Some(step_commitment.clone())))
                    .map_err(|e| anyhow!("[#{}] env write: {}", idx, e))?
                    .build()
                    .map_err(|e| anyhow!("[#{}] env build: {}", idx, e))?;
                (FOLD_ELF, env)
            }
        };

        let session = default_executor()
            .execute(env, elf)
            .map_err(|e| anyhow!("execute failed: {}", e))?;

        let segment_details: Vec<SegmentEstimate> = session
            .segments
            .iter()
            .map(|s| SegmentEstimate {
                cycles: s.cycles,
                po2: s.po2,
                estimated_seconds: calibration.map(|c| c.estimate_segment_seconds(s.po2)),
            })
            .collect();

        let total_cycles = session.cycles();
        let total_proving_cycles: u64 =
            segment_details.iter().map(|s| 1u64 << s.po2).sum();

        let estimated_seconds = calibration
            .map(|c| c.estimate_total_seconds(&segment_details));

        Ok(EstimateResult {
            total_cycles,
            total_proving_cycles,
            segments: segment_details.len(),
            segment_details,
            estimated_seconds,
        })
    }

    /// Run a calibration proof to measure this hardware's proving throughput.
    ///
    /// Uses a tree with 100 existing handles and 10 inserts to get a
    /// representative segment size for accurate time scaling.
    pub fn calibrate(&self) -> Result<CalibrationInfo> {
        // we need a large enough segment
        let request = build_bench_request(222, 15)?;

        let (exclusion_proof, zk_batch) = match &request {
            ProvingRequest::Step { exclusion_proof, zk_batch, .. } => {
                (exclusion_proof.clone(), zk_batch.clone())
            }
            _ => unreachable!(),
        };

        let build_env = || -> Result<ExecutorEnv<'static>> {
            ExecutorEnv::builder()
                .write(&(
                    exclusion_proof.clone(),
                    zk_batch.clone(),
                    STEP_ID,
                    FOLD_ID,
                ))
                .map_err(|e| anyhow!("calibrate env write: {}", e))?
                .build()
                .map_err(|e| anyhow!("calibrate env build: {}", e))
        };

        // Execute to get cycle count
        let session = default_executor()
            .execute(build_env()?, STEP_ELF)
            .map_err(|e| anyhow!("calibrate execute failed: {}", e))?;

        let calibration_po2 = session.segments.iter().map(|s| s.po2).max()
            .ok_or_else(|| anyhow!("calibration produced no segments"))?;
        let proving_cycles: u64 = session.segments.iter().map(|s| 1u64 << s.po2).sum();
        let num_segments = session.segments.len();

        // Prove to measure wall time
        let start = Instant::now();
        let _info = default_prover()
            .prove_with_opts(build_env()?, STEP_ELF, &ProverOpts::composite())
            .map_err(|e| anyhow!("calibrate prove failed: {}", e))?;
        let elapsed = start.elapsed().as_secs_f64();

        let seconds_per_segment = elapsed / num_segments as f64;
        let cycles_per_sec = proving_cycles as f64 / elapsed;

        Ok(CalibrationInfo {
            seconds_per_segment,
            calibration_po2,
            cycles_per_sec,
        })
    }

    /// Compress a STARK proof to SNARK (Groth16).
    pub fn compress(&self, input: &CompressInput) -> Result<Vec<u8>> {
        let receipt: Receipt = borsh::from_slice(&input.receipt)
            .map_err(|e| anyhow!("deserialize receipt: {}", e))?;

        let env = ExecutorEnv::builder()
            .add_assumption(receipt)
            .write(&(input.commitment.clone(), None::<Commitment>))
            .map_err(|e| anyhow!("env write: {}", e))?
            .build()
            .map_err(|e| anyhow!("env build: {}", e))?;

        let prover = default_prover();
        let opts = ProverOpts::groth16();
        let info = prover.prove_with_opts(env, FOLD_ELF, &opts)?;

        let receipt_bytes = borsh::to_vec(&info.receipt)
            .map_err(|e| anyhow!("serialize snark receipt: {}", e))?;

        Ok(receipt_bytes)
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}
