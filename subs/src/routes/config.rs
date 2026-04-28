//! Configuration routes for managing prover and registry endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::config::{KEY_PROVER_ENDPOINT, KEY_REGISTRY_ENDPOINT};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct TestEndpointRequest {
    pub endpoint: String,
}

#[derive(Serialize)]
pub struct TestEndpointResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ConfigResponse {
    pub prover_endpoint: Option<String>,
    pub registry_endpoint: Option<String>,
}

#[derive(Deserialize)]
pub struct SetConfigRequest {
    pub prover_endpoint: Option<String>,
    pub registry_endpoint: Option<String>,
}

#[derive(Serialize)]
pub struct SetConfigResponse {
    pub success: bool,
    pub prover_endpoint: Option<String>,
    pub registry_endpoint: Option<String>,
}

/// GET /config - Get current configuration
pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    let prover_endpoint = match state.config.prover_endpoint() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let registry_endpoint = match state.config.registry_endpoint() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    Json(ConfigResponse {
        prover_endpoint,
        registry_endpoint,
    })
    .into_response()
}

/// POST /config - Set configuration values
pub async fn set_config(
    State(state): State<AppState>,
    Json(req): Json<SetConfigRequest>,
) -> impl IntoResponse {
    // Set prover endpoint if provided
    if let Some(ref url) = req.prover_endpoint {
        if url.is_empty() {
            if let Err(e) = state.config.delete(KEY_PROVER_ENDPOINT) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        } else {
            if let Err(e) = state.config.set_prover_endpoint(url) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    }

    // Set registry endpoint if provided
    if let Some(ref url) = req.registry_endpoint {
        if url.is_empty() {
            if let Err(e) = state.config.delete(KEY_REGISTRY_ENDPOINT) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        } else {
            if let Err(e) = state.config.set_registry_endpoint(url) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    }

    // Return current config
    let prover_endpoint = state.config.prover_endpoint().ok().flatten();
    let registry_endpoint = state.config.registry_endpoint().ok().flatten();

    Json(SetConfigResponse {
        success: true,
        prover_endpoint,
        registry_endpoint,
    })
    .into_response()
}

/// POST /config/test/prover - Test prover endpoint connectivity
pub async fn test_prover(Json(req): Json<TestEndpointRequest>) -> impl IntoResponse {
    let endpoint = req.endpoint.trim_end_matches('/');

    // Try to connect to the prover's health endpoint
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let health_url = format!("{}/health", endpoint);

    match client.get(&health_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                Json(TestEndpointResponse {
                    success: true,
                    error: None,
                })
            } else {
                Json(TestEndpointResponse {
                    success: false,
                    error: Some(format!("Prover returned status: {}", response.status())),
                })
            }
        }
        Err(e) => Json(TestEndpointResponse {
            success: false,
            error: Some(format!("Connection failed: {}", e)),
        }),
    }
}

/// POST /config/test/registry - Test registry endpoint connectivity
pub async fn test_registry(Json(req): Json<TestEndpointRequest>) -> impl IntoResponse {
    let endpoint = req.endpoint.trim_end_matches('/');

    // Try to connect to the registry's health endpoint
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    // Try common health check paths
    let health_url = format!("{}/health", endpoint);

    match client.get(&health_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                Json(TestEndpointResponse {
                    success: true,
                    error: None,
                })
            } else if response.status().as_u16() == 404 {
                // Try root path if /health doesn't exist
                match client.get(endpoint).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() || resp.status().as_u16() < 500 {
                            Json(TestEndpointResponse {
                                success: true,
                                error: None,
                            })
                        } else {
                            Json(TestEndpointResponse {
                                success: false,
                                error: Some(format!("Registry returned status: {}", resp.status())),
                            })
                        }
                    }
                    Err(e) => Json(TestEndpointResponse {
                        success: false,
                        error: Some(format!("Connection failed: {}", e)),
                    }),
                }
            } else {
                Json(TestEndpointResponse {
                    success: false,
                    error: Some(format!("Registry returned status: {}", response.status())),
                })
            }
        }
        Err(e) => Json(TestEndpointResponse {
            success: false,
            error: Some(format!("Connection failed: {}", e)),
        }),
    }
}
