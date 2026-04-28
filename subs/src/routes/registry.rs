//! Registry integration routes.
//!
//! These routes allow subsd to pull pending handles from a configured registry
//! server and notify it when handles are committed.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use super::json_error;

#[derive(Serialize)]
pub struct SyncResponse {
    pub success: bool,
    pub pulled: usize,
    pub staged: usize,
    pub errors: Vec<String>,
}

#[derive(Deserialize)]
struct RegistryPendingResponse {
    handles: Vec<PendingHandle>,
}

#[derive(Deserialize)]
struct PendingHandle {
    handle: String,
    script_pubkey: String,
}

/// POST /registry/sync - Pull pending handles from registry and stage them
///
/// Only works when registry_endpoint is configured in settings.
pub async fn sync_from_registry(State(state): State<AppState>) -> Result<Json<SyncResponse>, impl IntoResponse> {
    // Check if registry endpoint is configured
    let registry_endpoint = match state.config.registry_endpoint() {
        Ok(Some(url)) => url,
        Ok(None) => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "registry_endpoint not configured. Set it in Settings.",
            ));
        }
        Err(e) => {
            return Err(json_error(StatusCode::INTERNAL_SERVER_ERROR, e));
        }
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    // Fetch pending handles from registry
    let pending_url = format!("{}/pending", registry_endpoint.trim_end_matches('/'));
    let response = match client.get(&pending_url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Err(json_error(
                StatusCode::BAD_GATEWAY,
                format!("Failed to connect to registry: {}", e),
            ));
        }
    };

    if !response.status().is_success() {
        return Err(json_error(
            StatusCode::BAD_GATEWAY,
            format!("Registry returned status: {}", response.status()),
        ));
    }

    let pending: RegistryPendingResponse = match response.json().await {
        Ok(p) => p,
        Err(e) => {
            return Err(json_error(
                StatusCode::BAD_GATEWAY,
                format!("Invalid response from registry: {}", e),
            ));
        }
    };

    if pending.handles.is_empty() {
        return Ok(Json(SyncResponse {
            success: true,
            pulled: 0,
            staged: 0,
            errors: vec![],
        }));
    }

    tracing::info!("Pulled {} pending handles from registry", pending.handles.len());

    // Build handle requests
    let mut requests = Vec::new();
    let mut errors = Vec::new();
    let mut staged_handles = Vec::new();

    for handle in &pending.handles {
        // Parse the handle name
        let handle_name: spaces_protocol::sname::SName = match handle.handle.parse() {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!("{}: invalid handle: {}", handle.handle, e));
                continue;
            }
        };

        requests.push(subs_core::HandleRequest {
            handle: handle_name,
            script_pubkey: handle.script_pubkey.clone(),
            dev_private_key: None,
        });
        staged_handles.push(handle.handle.clone());
    }

    // Stage all handles at once
    let staged = if !requests.is_empty() {
        match state.operator.add_requests(requests).await {
            Ok(result) => {
                tracing::info!("Staged {} handles", result.total_added);
                for space_result in &result.by_space {
                    for skip in &space_result.skipped {
                        tracing::info!("Skipped: {} ({:?})", skip.handle, skip.reason);
                    }
                }
                result.total_added
            }
            Err(e) => {
                errors.push(format!("Failed to stage handles: {}", e));
                0
            }
        }
    } else {
        0
    };

    // Acknowledge the handles we processed (even if already staged)
    if !staged_handles.is_empty() {
        let ack_url = format!("{}/ack", registry_endpoint.trim_end_matches('/'));

        #[derive(Serialize)]
        struct AckRequest {
            handles: Vec<String>,
        }

        let ack_req = AckRequest {
            handles: staged_handles,
        };

        if let Err(e) = client.post(&ack_url).json(&ack_req).send().await {
            tracing::warn!("Failed to acknowledge handles to registry: {}", e);
        }
    }

    Ok(Json(SyncResponse {
        success: errors.is_empty(),
        pulled: pending.handles.len(),
        staged,
        errors,
    }))
}

#[derive(Deserialize)]
pub struct NotifyRequest {
    /// Space to notify about (e.g., "@example")
    pub space: String,
    /// Commitment root
    pub root: String,
}

#[derive(Serialize)]
pub struct NotifyResponse {
    pub success: bool,
    pub notified: usize,
    pub message: Option<String>,
}

/// POST /registry/notify - Notify registry that handles were committed
///
/// Call this after a commitment is finalized to update the registry.
pub async fn notify_registry(
    State(state): State<AppState>,
    Json(req): Json<NotifyRequest>,
) -> Result<Json<NotifyResponse>, impl IntoResponse> {
    // Check if registry endpoint is configured
    let registry_endpoint = match state.config.registry_endpoint() {
        Ok(Some(url)) => url,
        Ok(None) => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "registry_endpoint not configured",
            ));
        }
        Err(e) => {
            return Err(json_error(StatusCode::INTERNAL_SERVER_ERROR, e));
        }
    };

    let space_label = req.space.parse().map_err(|e| {
        json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e))
    })?;

    // Get handles for this commitment root
    let handles = state
        .operator
        .get_handles_by_commitment(&space_label, &req.root)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if handles.is_empty() {
        return Ok(Json(NotifyResponse {
            success: true,
            notified: 0,
            message: Some("No handles found for this commitment".to_string()),
        }));
    }

    // Build handle names (name@space format)
    let space_suffix = req.space.trim_start_matches('@');
    let handle_names: Vec<String> = handles
        .iter()
        .map(|h| format!("{}@{}", h.name, space_suffix))
        .collect();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let webhook_url = format!("{}/webhook/committed", registry_endpoint.trim_end_matches('/'));

    #[derive(Serialize)]
    struct WebhookPayload {
        root: String,
        handles: Vec<String>,
    }

    let payload = WebhookPayload {
        root: req.root,
        handles: handle_names.clone(),
    };

    let response = match client.post(&webhook_url).json(&payload).send().await {
        Ok(r) => r,
        Err(e) => {
            return Err(json_error(
                StatusCode::BAD_GATEWAY,
                format!("Failed to notify registry: {}", e),
            ));
        }
    };

    if !response.status().is_success() {
        return Err(json_error(
            StatusCode::BAD_GATEWAY,
            format!("Registry webhook returned: {}", response.status()),
        ));
    }

    Ok(Json(NotifyResponse {
        success: true,
        notified: handle_names.len(),
        message: None,
    }))
}

#[derive(Serialize)]
pub struct RegistryStatusResponse {
    pub configured: bool,
    pub endpoint: Option<String>,
}

/// GET /registry/status - Check if registry is configured
pub async fn registry_status(State(state): State<AppState>) -> impl IntoResponse {
    let endpoint = state.config.registry_endpoint().ok().flatten();

    Json(RegistryStatusResponse {
        configured: endpoint.is_some(),
        endpoint,
    })
}
