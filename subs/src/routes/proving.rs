//! Proving endpoints.
//!
//! Binary format for efficiency:
//! - GET /proving/next returns borsh-serialized Option<ProvingRequest>
//! - POST /proving/fulfill accepts: commitment_id (8 bytes) + request_type (1 byte) + receipt

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use subs_core::CompressInput;

use crate::state::AppState;
use super::json_error;

/// Request type for fulfill payload
const REQUEST_TYPE_STEP: u8 = 0;
const REQUEST_TYPE_FOLD: u8 = 1;

/// GET /spaces/:space/proving/next - Get next proving request (binary borsh format)
pub async fn get_next(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Response, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let request = state
        .operator
        .get_next_proving_request(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Serialize as borsh
    let bytes = borsh::to_vec(&request)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, format!("serialize error: {}", e)))?;

    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    ).into_response())
}

#[derive(Serialize)]
pub struct FulfillResponse {
    pub success: bool,
    pub message: Option<String>,
}

/// POST /spaces/:space/proving/fulfill - Submit proof receipt (binary format)
///
/// Binary payload format:
/// - 8 bytes: commitment_id (i64 little-endian)
/// - 1 byte: request_type (0 = Step, 1 = Fold)
/// - remaining: receipt bytes
pub async fn fulfill(
    State(state): State<AppState>,
    Path(space): Path<String>,
    body: Bytes,
) -> Result<Json<FulfillResponse>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // Parse binary payload
    if body.len() < 9 {
        return Err(json_error(StatusCode::BAD_REQUEST, "payload too short: need commitment_id (8) + type (1) + receipt"));
    }

    let commitment_id = i64::from_le_bytes(body[0..8].try_into().unwrap());
    let request_type = body[8];
    let receipt_bytes = &body[9..];

    if receipt_bytes.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, "empty receipt"));
    }

    let is_fold = match request_type {
        REQUEST_TYPE_STEP => false,
        REQUEST_TYPE_FOLD => true,
        _ => return Err(json_error(StatusCode::BAD_REQUEST, format!("invalid request_type: {}", request_type))),
    };

    state
        .operator
        .fulfill_request_by_id(&space, commitment_id, is_fold, receipt_bytes)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(FulfillResponse { success: true, message: None }))
}

#[derive(Serialize)]
pub struct CompressInputResponse {
    pub input: Option<CompressInputJson>,
}

#[derive(Serialize)]
pub struct CompressInputJson {
    /// Base64-encoded receipt
    pub receipt: String,
    pub commitment: subs_types::Commitment,
}

/// GET /spaces/:space/compress - Get SNARK compression input
pub async fn get_compress_input(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<CompressInputResponse>, Response> {
    use base64::Engine;

    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let input = state
        .operator
        .get_compress_input(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let response = match input {
        Some(CompressInput { receipt, commitment }) => CompressInputResponse {
            input: Some(CompressInputJson {
                receipt: base64::engine::general_purpose::STANDARD.encode(&receipt),
                commitment,
            }),
        },
        None => CompressInputResponse { input: None },
    };

    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct SaveSnarkBody {
    /// Base64-encoded SNARK receipt
    pub receipt: String,
}

#[derive(Serialize)]
pub struct SaveSnarkResponse {
    pub success: bool,
}

/// POST /spaces/:space/snark - Save compressed SNARK
pub async fn save_snark(
    State(state): State<AppState>,
    Path(space): Path<String>,
    Json(body): Json<SaveSnarkBody>,
) -> Result<Json<SaveSnarkResponse>, Response> {
    use base64::Engine;

    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let receipt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.receipt)
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid base64: {}", e)))?;

    state
        .operator
        .save_snark(&space, &receipt_bytes)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(SaveSnarkResponse { success: true }))
}

// --- Push-based proving with external prover server ---

#[derive(Serialize)]
pub struct PushResponse {
    pub success: bool,
    pub job_id: Option<String>,
    pub message: Option<String>,
}

/// POST /spaces/:space/proving/push - Push proving request to configured prover server
///
/// Returns immediately with a job_id. Use /proving/poll to check status.
pub async fn push_to_prover(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<PushResponse>, Response> {
    let space_label = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // Check if prover endpoint is configured
    let prover_endpoint = state
        .config
        .prover_endpoint()
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "prover_endpoint not configured. Set it via POST /config",
            )
        })?;

    // Get the next proving request
    let request = state
        .operator
        .get_next_proving_request(&space_label)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let Some(request) = request else {
        return Ok(Json(PushResponse {
            success: false,
            job_id: None,
            message: Some("no pending proving request".to_string()),
        }));
    };

    // Serialize the request
    let request_bytes = borsh::to_vec(&request)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, format!("serialize error: {}", e)))?;

    // Submit to prover server
    let client = reqwest::Client::new();
    let prove_url = format!("{}/prove", prover_endpoint.trim_end_matches('/'));

    let response = client
        .post(&prove_url)
        .header("Content-Type", "application/octet-stream")
        .body(request_bytes)
        .send()
        .await
        .map_err(|e| json_error(StatusCode::BAD_GATEWAY, format!("prover request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(json_error(
            StatusCode::BAD_GATEWAY,
            format!("prover returned {}: {}", status, body),
        ));
    }

    #[derive(Deserialize)]
    struct ProverSubmitResponse {
        job_id: String,
    }

    let submit_response: ProverSubmitResponse = response
        .json()
        .await
        .map_err(|e| json_error(StatusCode::BAD_GATEWAY, format!("invalid prover response: {}", e)))?;

    // Store the job info (space:commitment_id:is_fold -> job_id)
    let commitment_id = match &request {
        subs_core::ProvingRequest::Step { commitment_id, .. } => commitment_id,
        subs_core::ProvingRequest::Fold { commitment_id, .. } => commitment_id,
    };
    let is_fold = matches!(&request, subs_core::ProvingRequest::Fold { .. });

    let job_key = format!("job:{}:{}:{}", space, commitment_id, if is_fold { "fold" } else { "step" });
    state
        .config
        .set(&job_key, &submit_response.job_id)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(PushResponse {
        success: true,
        job_id: Some(submit_response.job_id),
        message: Some("proving request submitted to prover".to_string()),
    }))
}

#[derive(Serialize)]
pub struct PollResponse {
    pub success: bool,
    pub status: Option<String>,
    pub complete: bool,
    pub message: Option<String>,
}

/// POST /spaces/:space/proving/poll - Poll prover for job completion and save receipt
pub async fn poll_prover(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<PollResponse>, Response> {
    let space_label = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // Check if prover endpoint is configured
    let prover_endpoint = state
        .config
        .prover_endpoint()
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "prover_endpoint not configured",
            )
        })?;

    // Get the next proving request to know what we're looking for
    let request = state
        .operator
        .get_next_proving_request(&space_label)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let Some(request) = request else {
        return Ok(Json(PollResponse {
            success: true,
            status: None,
            complete: true,
            message: Some("no pending proving request".to_string()),
        }));
    };

    let commitment_id = match &request {
        subs_core::ProvingRequest::Step { commitment_id, .. } => *commitment_id,
        subs_core::ProvingRequest::Fold { commitment_id, .. } => *commitment_id,
    };
    let is_fold = matches!(&request, subs_core::ProvingRequest::Fold { .. });

    // Look up the job_id
    let job_key = format!("job:{}:{}:{}", space, commitment_id, if is_fold { "fold" } else { "step" });
    let job_id = state
        .config
        .get(&job_key)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "no job found - use /proving/push first",
            )
        })?;

    // Check job status
    let client = reqwest::Client::new();
    let status_url = format!("{}/jobs/{}", prover_endpoint.trim_end_matches('/'), job_id);

    let response = client
        .get(&status_url)
        .send()
        .await
        .map_err(|e| json_error(StatusCode::BAD_GATEWAY, format!("prover request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(json_error(
            StatusCode::BAD_GATEWAY,
            format!("prover returned {}: {}", status, body),
        ));
    }

    #[derive(Deserialize)]
    struct JobStatusResponse {
        status: String,
        error: Option<String>,
    }

    let job_status: JobStatusResponse = response
        .json()
        .await
        .map_err(|e| json_error(StatusCode::BAD_GATEWAY, format!("invalid prover response: {}", e)))?;

    match job_status.status.as_str() {
        "complete" => {
            // Download the receipt
            let receipt_url = format!("{}/jobs/{}/receipt", prover_endpoint.trim_end_matches('/'), job_id);
            let receipt_response = client
                .get(&receipt_url)
                .send()
                .await
                .map_err(|e| json_error(StatusCode::BAD_GATEWAY, format!("receipt download failed: {}", e)))?;

            if !receipt_response.status().is_success() {
                return Err(json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("receipt download failed: {}", receipt_response.status()),
                ));
            }

            let receipt_bytes = receipt_response
                .bytes()
                .await
                .map_err(|e| json_error(StatusCode::BAD_GATEWAY, format!("receipt read failed: {}", e)))?;

            // Save the receipt
            state
                .operator
                .fulfill_request_by_id(&space_label, commitment_id, is_fold, &receipt_bytes)
                .await
                .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

            // Clean up job key
            let _ = state.config.delete(&job_key);

            Ok(Json(PollResponse {
                success: true,
                status: Some("complete".to_string()),
                complete: true,
                message: Some("proof complete and saved".to_string()),
            }))
        }
        "failed" => {
            // Clean up job key
            let _ = state.config.delete(&job_key);

            Ok(Json(PollResponse {
                success: false,
                status: Some("failed".to_string()),
                complete: true,
                message: job_status.error,
            }))
        }
        status => {
            Ok(Json(PollResponse {
                success: true,
                status: Some(status.to_string()),
                complete: false,
                message: None,
            }))
        }
    }
}

/// GET /spaces/:space/proving/estimate - Get proving time estimate from configured prover
pub async fn get_estimate(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Response, Response> {
    let space_label = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let prover_endpoint = state
        .config
        .prover_endpoint()
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "prover_endpoint not configured"))?;

    let request = state
        .operator
        .get_next_proving_request(&space_label)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let Some(request) = request else {
        return Err(json_error(StatusCode::NOT_FOUND, "no pending proving request"));
    };

    let request_bytes = borsh::to_vec(&request)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {}", e)))?;

    let client = reqwest::Client::new();
    let url = format!("{}/estimate", prover_endpoint.trim_end_matches('/'));

    let response = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .body(request_bytes)
        .send()
        .await
        .map_err(|e| json_error(StatusCode::BAD_GATEWAY, format!("prover request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(json_error(StatusCode::BAD_GATEWAY, format!("prover returned {}: {}", status, body)));
    }

    // Forward the JSON response from the prover as-is (arbitrary key/values)
    let estimate: serde_json::Value = response
        .json()
        .await
        .map_err(|e| json_error(StatusCode::BAD_GATEWAY, format!("invalid prover response: {}", e)))?;

    Ok((StatusCode::OK, Json(estimate)).into_response())
}
