//! Certificate endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
    response::Response,
};
use base64::Engine;
use serde::Serialize;

use crate::state::AppState;
use super::json_error;

#[derive(Serialize)]
pub struct IssueCertResponse {
    /// Base64-encoded root certificate
    pub root_cert: String,
    /// Base64-encoded handle certificate (null for space-only certs)
    pub handle_cert: Option<String>,
}

/// GET /certs/:handle - Issue certificate for handle
///
/// Handle can be:
/// - `@space` - issues root certificate only
/// - `alice@space` - issues root + handle certificate
pub async fn issue_cert(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Json<IssueCertResponse>, Response> {
    use spaces_protocol::sname::SName;

    let handle: SName = handle
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid handle: {}", e)))?;

    let (root_cert, handle_cert) = state
        .operator
        .issue_cert(&handle)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let root_bytes = borsh::to_vec(&root_cert)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to serialize root cert: {}", e)))?;

    let handle_bytes = match handle_cert {
        Some(cert) => Some(
            borsh::to_vec(&cert)
                .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to serialize handle cert: {}", e)))?
        ),
        None => None,
    };

    Ok(Json(IssueCertResponse {
        root_cert: base64::engine::general_purpose::STANDARD.encode(&root_bytes),
        handle_cert: handle_bytes.map(|b| base64::engine::general_purpose::STANDARD.encode(&b)),
    }))
}

