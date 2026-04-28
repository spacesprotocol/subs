//! Shared types for subs and subs-prover.

pub use libveritas_zk::guest::Commitment;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A request for the next proof that needs to be generated.
///
/// This type is shared between the subs operator and the subs-prover.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum ProvingRequest {
    Step {
        commitment_id: i64,
        idx: usize,
        prev_root: Option<String>,
        root: String,
        exclusion_proof: Vec<u8>,
        zk_batch: Vec<u8>,
    },
    Fold {
        commitment_id: i64,
        idx: usize,
        prev_root: Option<String>,
        root: String,
        acc_receipt: Vec<u8>,
        acc_commitment: Commitment,
        step_receipt: Vec<u8>,
        step_commitment: Commitment,
    },
}

impl ProvingRequest {
    pub fn commitment_id(&self) -> i64 {
        match self {
            ProvingRequest::Step { commitment_id, .. } => *commitment_id,
            ProvingRequest::Fold { commitment_id, .. } => *commitment_id,
        }
    }

    pub fn idx(&self) -> usize {
        match self {
            ProvingRequest::Step { idx, .. } => *idx,
            ProvingRequest::Fold { idx, .. } => *idx,
        }
    }
}

/// Input data needed for SNARK compression.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CompressInput {
    pub receipt: Vec<u8>,
    pub commitment: Commitment,
}

/// Result from executing a proving request without actually proving.
/// Used to estimate cycle counts and proving time.
#[derive(Clone, Serialize, Deserialize)]
pub struct EstimateResult {
    /// Total user cycles across all segments.
    pub total_cycles: u64,
    /// Total proving cycles (padded to power-of-2 per segment).
    pub total_proving_cycles: u64,
    /// Number of segments.
    pub segments: usize,
    /// Per-segment breakdown.
    pub segment_details: Vec<SegmentEstimate>,
    /// Estimated total proving time in seconds (if calibrated).
    pub estimated_seconds: Option<f64>,
}

/// Cycle estimate for a single segment.
#[derive(Clone, Serialize, Deserialize)]
pub struct SegmentEstimate {
    /// User cycles (actual execution).
    pub cycles: u32,
    /// Power-of-2 proving size.
    pub po2: u32,
    /// Estimated proving time for this segment in seconds (if calibrated).
    pub estimated_seconds: Option<f64>,
}

/// Calibration result from benchmarking proving throughput.
#[derive(Clone, Serialize, Deserialize)]
pub struct CalibrationInfo {
    /// Seconds it took to prove the calibration segment.
    pub seconds_per_segment: f64,
    /// The po2 of the calibration segment.
    pub calibration_po2: u32,
    /// Derived: proving cycles per second.
    pub cycles_per_sec: f64,
}

impl CalibrationInfo {
    /// Estimate proving time for a segment with the given po2.
    pub fn estimate_segment_seconds(&self, po2: u32) -> f64 {
        // Time scales with 2^po2
        self.seconds_per_segment * (1u64 << po2) as f64 / (1u64 << self.calibration_po2) as f64
    }

    /// Estimate total proving time for a set of segments.
    pub fn estimate_total_seconds(&self, segments: &[SegmentEstimate]) -> f64 {
        segments.iter().map(|s| self.estimate_segment_seconds(s.po2)).sum()
    }
}
