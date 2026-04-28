//! Commit endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
    response::Response,
};
use serde::{Deserialize, Serialize};
use subs_core::{PipelineStatus, SpaceCommitResult};

use crate::state::AppState;
use super::json_error;

/// Recommended fee rates from mempool.space
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFees {
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

/// Fetch recommended fees from mempool.space API
async fn fetch_recommended_fees() -> Option<RecommendedFees> {
    let url = "https://mempool.space/api/v1/fees/recommended";

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    client
        .get(url)
        .send()
        .await
        .ok()?
        .json::<RecommendedFees>()
        .await
        .ok()
}

/// GET /fees - Get recommended fee rates
pub async fn get_fees() -> Result<Json<RecommendedFees>, Response> {
    match fetch_recommended_fees().await {
        Some(fees) => Ok(Json(fees)),
        None => Err(json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "could not fetch fee rates from mempool.space",
        )),
    }
}

#[derive(Deserialize)]
pub struct CommitBody {
    #[serde(default)]
    pub dry_run: bool,
}

/// POST /spaces/{space}/commit - Commit staged handles locally
pub async fn commit_local(
    State(state): State<AppState>,
    Path(space): Path<String>,
    Json(body): Json<CommitBody>,
) -> Result<Json<SpaceCommitResult>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    if body.dry_run {
        // For dry run, check if commit is possible
        if let Some(reason) = state
            .operator
            .can_commit_local(&space)
            .await
            .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?
        {
            return Err(json_error(StatusCode::BAD_REQUEST, format!("cannot commit: {}", reason)));
        }
        // Return empty result for dry run
        return Ok(Json(SpaceCommitResult {
            space: space.clone(),
            prev_root: None,
            root: String::new(),
            handles_committed: 0,
            is_initial: false,
        }));
    }

    state
        .operator
        .commit_local(&space)
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Deserialize)]
pub struct BroadcastBody {
    #[serde(default)]
    pub fee_rate: Option<f64>,
}

#[derive(Serialize)]
pub struct BroadcastResponse {
    pub txid: String,
}

/// POST /spaces/:space/broadcast - Broadcast commit on-chain
pub async fn broadcast(
    State(state): State<AppState>,
    Path(space): Path<String>,
    Json(body): Json<BroadcastBody>,
) -> Result<Json<BroadcastResponse>, Response> {
    use bitcoin::FeeRate;

    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let fee_rate = body.fee_rate.map(|r| FeeRate::from_sat_per_vb_unchecked(r as u64));

    let txid = state
        .operator
        .commit(&space, fee_rate)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(BroadcastResponse {
        txid: txid.to_string(),
    }))
}

#[derive(Serialize)]
pub struct CommitStatusResponse {
    pub status: String,
    pub txid: Option<String>,
    pub block_height: Option<u32>,
    pub confirmations: Option<u32>,
}

/// GET /spaces/{space}/commit/status - Get on-chain commit status
pub async fn get_commit_status(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<CommitStatusResponse>, Response> {
    use subs_core::app::CommitStatus;

    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let status = state
        .operator
        .get_commit_status(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let response = match status {
        CommitStatus::None => CommitStatusResponse {
            status: "none".to_string(),
            txid: None,
            block_height: None,
            confirmations: None,
        },
        CommitStatus::Pending { txid, .. } => CommitStatusResponse {
            status: "pending".to_string(),
            txid: Some(txid.to_string()),
            block_height: None,
            confirmations: None,
        },
        CommitStatus::Confirmed {
            txid,
            block_height,
            confirmations,
        } => CommitStatusResponse {
            status: "confirmed".to_string(),
            txid: Some(txid.to_string()),
            block_height: Some(block_height),
            confirmations: Some(confirmations),
        },
        CommitStatus::Finalized { block_height } => CommitStatusResponse {
            status: "finalized".to_string(),
            txid: None,
            block_height: Some(block_height),
            confirmations: None,
        },
    };

    Ok(Json(response))
}

/// Maximum handles to publish per request to avoid oversized relay messages.
const PUBLISH_BATCH_SIZE: usize = 100;

#[derive(Serialize)]
pub struct PublishResponse {
    pub handles_published: usize,
    pub remaining: usize,
}

#[derive(Deserialize, Default)]
pub struct PublishBody {
    /// Publish only these specific handles (empty = all unpublished)
    #[serde(default)]
    pub handles: Vec<String>,
}

/// POST /spaces/:space/publish - Publish certificates in batches
pub async fn publish_certs(
    State(state): State<AppState>,
    Path(space): Path<String>,
    body: Option<Json<PublishBody>>,
) -> Result<Json<PublishResponse>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let handles = body.map(|b| b.0.handles).unwrap_or_default();

    let (count, remaining) = state
        .operator
        .publish_certs(&space, PUBLISH_BATCH_SIZE, &handles)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(PublishResponse {
        handles_published: count,
        remaining,
    }))
}

/// POST /spaces/:space/rollback-local - Rollback the last unbroadcast local commitment
pub async fn rollback_local(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let space_label: spaces_protocol::slabel::SLabel = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // Grab any in-flight proving job info before rollback so we can clean up
    let proving_request = state
        .operator
        .get_next_proving_request(&space_label)
        .await
        .ok()
        .flatten();

    state
        .operator
        .rollback_local(&space_label)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Clean up any prover job keys for the rolled-back commitment
    if let Some(req) = proving_request {
        let cid = req.commitment_id();
        let step_key = format!("job:{}:{}:step", space, cid);
        let fold_key = format!("job:{}:{}:fold", space, cid);
        let _ = state.config.delete(&step_key);
        let _ = state.config.delete(&fold_key);
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ParkBody {
    #[serde(default)]
    pub handles: Vec<String>,
    #[serde(default)]
    pub parked: bool,
    /// Bulk mode: park/unpark all staged handles matching search/filter
    pub search: Option<String>,
    pub filter: Option<String>,
}

/// POST /spaces/:space/park - Park or unpark staged handles
pub async fn park_handles(
    State(state): State<AppState>,
    Path(space): Path<String>,
    Json(body): Json<ParkBody>,
) -> Result<Json<serde_json::Value>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let count = state
        .operator
        .set_parked(&space, &body.handles, body.parked, body.search, body.filter)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(serde_json::json!({ "updated": count })))
}

#[derive(Deserialize)]
pub struct RemoveBody {
    #[serde(default)]
    pub handles: Vec<String>,
    pub search: Option<String>,
    pub filter: Option<String>,
}

/// POST /spaces/:space/remove - Remove staged handles
pub async fn remove_handles(
    State(state): State<AppState>,
    Path(space): Path<String>,
    Json(body): Json<RemoveBody>,
) -> Result<Json<serde_json::Value>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let count = state
        .operator
        .remove_staged(&space, &body.handles, body.search, body.filter)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(serde_json::json!({ "removed": count })))
}

/// GET /spaces/:space/pipeline - Get commitment pipeline status for stepper UI
/// Extended pipeline status with prover config info for the UI
#[derive(Serialize)]
pub struct PipelineResponse {
    #[serde(flatten)]
    pub status: PipelineStatus,
    /// Whether a prover endpoint is configured in settings
    pub prover_configured: bool,
    /// Whether a proving job is currently in flight on the prover
    pub proving_job_active: bool,
}

pub async fn get_pipeline_status(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<PipelineResponse>, Response> {
    let space_label: spaces_protocol::slabel::SLabel = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // Ensure space is loaded
    state
        .operator
        .load_or_create_space(&space_label)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let status = state
        .operator
        .get_pipeline_status(&space_label)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let prover_configured = state.config.prover_endpoint().unwrap_or(None).is_some();

    // Check if there's an active proving job by looking for a job key in config.
    // The job key uses the commitment's SQLite row id from the proving request,
    // matching the format used by push_to_prover and the background loop.
    let proving_job_active = if status.commitment_idx.is_some() {
        if let Ok(Some(req)) = state.operator.get_next_proving_request(&space_label).await {
            let cid = req.commitment_id();
            let is_fold = matches!(&req, subs_types::ProvingRequest::Fold { .. });
            let kind = if is_fold { "fold" } else { "step" };
            let job_key = format!("job:{}:{}:{}", space, cid, kind);
            state.config.get(&job_key).unwrap_or(None).is_some()
        } else {
            false
        }
    } else {
        false
    };

    Ok(Json(PipelineResponse {
        status,
        prover_configured,
        proving_job_active,
    }))
}
