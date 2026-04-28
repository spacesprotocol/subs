//! Status and spaces endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
    response::Response,
};
use serde::{Deserialize, Serialize};
use subs_core::{HandlesListResult, SpaceStatus, StatusResult};

use crate::state::AppState;
use super::json_error;

/// GET /status - Get status of all spaces
pub async fn get_status(
    State(state): State<AppState>,
) -> Result<Json<StatusResult>, Response> {
    state
        .operator
        .status()
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Serialize)]
pub struct SpacesListResponse {
    pub spaces: Vec<String>,
}

/// GET /spaces - List all loaded spaces
pub async fn list_spaces(
    State(state): State<AppState>,
) -> Json<SpacesListResponse> {
    let spaces = state
        .operator
        .list_spaces()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    Json(SpacesListResponse { spaces })
}

/// GET /spaces/:space - Get status of specific space
pub async fn get_space_status(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<SpaceStatus>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // Ensure space is loaded
    state
        .operator
        .load_or_create_space(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    state
        .operator
        .get_space_status(&space)
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Serialize)]
pub struct OperateResponse {
    pub success: bool,
    pub space: String,
}

/// POST /spaces/:space/operate - Check if we can operate and add space
pub async fn operate_space(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<OperateResponse>, Response> {
    let space_label = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // This will check if wallet can operate the space and create it if so
    state
        .operator
        .load_or_create_space(&space_label)
        .await
        .map_err(|e| {
            // Check if it's a "cannot operate" error
            let msg = e.to_string();
            if msg.contains("cannot operate") || msg.contains("not delegated") {
                json_error(
                    StatusCode::FORBIDDEN,
                    format!("Space {} is not delegated to this operator. Ask the owner to delegate it first.", space),
                )
            } else {
                json_error(StatusCode::INTERNAL_SERVER_ERROR, e)
            }
        })?;

    Ok(Json(OperateResponse {
        success: true,
        space,
    }))
}

#[derive(Deserialize)]
pub struct HandlesQuery {
    #[serde(default = "default_page")]
    pub page: usize,
    #[serde(default = "default_per_page")]
    pub per_page: usize,
    pub search: Option<String>,
    pub filter: Option<String>,
}

fn default_page() -> usize { 1 }
fn default_per_page() -> usize { 20 }

/// GET /spaces/:space/handles/:handle - Get a single handle by name
pub async fn get_handle(
    State(state): State<AppState>,
    Path((space, handle)): Path<(String, String)>,
) -> Result<Json<subs_core::HandleInfo>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    state
        .operator
        .load_or_create_space(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let handle_info = state
        .operator
        .get_handle_info(&space, &handle)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    match handle_info {
        Some(h) => Ok(Json(h)),
        None => Err(json_error(StatusCode::NOT_FOUND, "handle not found")),
    }
}

/// GET /spaces/:space/handles - List handles with pagination
pub async fn list_handles(
    State(state): State<AppState>,
    Path(space): Path<String>,
    Query(query): Query<HandlesQuery>,
) -> Result<Json<HandlesListResult>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // Ensure space is loaded
    state
        .operator
        .load_or_create_space(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    state
        .operator
        .list_handles(&space, query.page, query.per_page, query.search, query.filter)
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}
