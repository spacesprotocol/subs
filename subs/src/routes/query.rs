//! Query endpoint for resolving handles via fabric.

use axum::{
    extract::State,
    http::{header, StatusCode},
    Json,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::state::AppState;
use super::json_error;

#[derive(Deserialize)]
pub struct QueryBody {
    pub handle: String,
}

/// POST /query - Resolve one or more comma-separated handles via the fabric network
pub async fn resolve_handle(
    State(state): State<AppState>,
    Json(body): Json<QueryBody>,
) -> Result<Json<Vec<subs_core::app::ResolvedZone>>, Response> {
    let handles: Vec<&str> = body.handle.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if handles.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, anyhow::anyhow!("no handles provided")));
    }
    state
        .operator
        .resolve(&handles)
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}

/// GET /query/message?handle=... - Export the binary .spacemsg for a handle
pub async fn export_message(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<QueryBody>,
) -> Result<Response, Response> {
    let handle = params.handle.trim();
    if handle.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, anyhow::anyhow!("handle required")));
    }

    let bundle = state
        .operator
        .export_message(handle)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"query.spacemsg\""),
        ],
        bundle.message,
    ).into_response())
}

/// POST /query/anchors - Get root anchors as JSON
pub async fn export_anchors(
    State(state): State<AppState>,
) -> Result<Response, Response> {
    let rpc = state.operator.rpc()
        .ok_or_else(|| json_error(StatusCode::SERVICE_UNAVAILABLE, "RPC not available"))?;

    use spaces_client::rpc::RpcClient;
    let anchors = rpc.get_root_anchors().await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let json = serde_json::to_vec_pretty(&anchors)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"anchors.json\""),
        ],
        json,
    ).into_response())
}
