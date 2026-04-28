//! Example Registry Server for Subs
//!
//! This is a simple example showing how to build a registry server that:
//! 1. Accepts handle registration requests from users (public API)
//! 2. Exposes pending handles for subsd to pull
//! 3. Receives webhooks from subsd when handles are committed
//!
//! Architecture:
//! ```
//! ┌─────────┐     ┌──────────────────┐     ┌─────────┐
//! │  Users  │────>│  Registry Server │<────│  subsd  │
//! └─────────┘     └──────────────────┘     └─────────┘
//!                   (public)                 (private)
//! ```
//!
//! - Users submit registrations to the registry (public)
//! - subsd pulls pending handles from the registry
//! - subsd calls webhook when handles are committed
//!
//! In production, you would customize this to:
//! - Add authentication for users
//! - Add API key auth for subsd endpoints
//! - Validate handle requests (e.g., check payment, verify identity)
//! - Store registration state in a database
//! - Send notifications to users when their handles are committed
//!
//! # Usage
//!
//! ```bash
//! registry-server --port 8080
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[derive(Parser)]
#[command(
    name = "registry-server",
    about = "Example registry server for subs handle registration",
    version
)]
struct Cli {
    /// Server port
    #[arg(short, long, default_value = "8080")]
    port: u16,
}

/// Shared application state
struct AppState {
    /// In-memory store of registrations (in production, use a database)
    registrations: RwLock<Vec<Registration>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Registration {
    handle: String,
    script_pubkey: String,
    status: RegistrationStatus,
    commitment_root: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum RegistrationStatus {
    Pending,    // Waiting to be pulled by subsd
    Staged,     // Pulled by subsd, waiting for commit
    Committed,  // On-chain
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "registry_server=info,tower_http=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    let state = Arc::new(AppState {
        registrations: RwLock::new(Vec::new()),
    });

    let app = Router::new()
        // Health check
        .route("/health", get(health))

        // Public endpoints (for users)
        .route("/register", post(register_handle))
        .route("/status/:handle", get(get_status))

        // Private endpoints (for subs to call). In production, protect these with API key auth.
        .route("/pending", get(get_pending_handles))
        .route("/ack", post(ack_handles))
        .route("/webhook/committed", post(webhook_committed))

        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    tracing::info!("Registry server starting on http://{}", addr);
    tracing::info!("");
    tracing::info!("Public endpoints (for users):");
    tracing::info!("  POST /register     - Register a handle");
    tracing::info!("  GET  /status/:h    - Check registration status");
    tracing::info!("");
    tracing::info!("Private endpoints (for subsd):");
    tracing::info!("  GET  /pending      - Get pending handles");
    tracing::info!("  POST /ack          - Acknowledge handles were staged");
    tracing::info!("  POST /webhook/committed - Notify committed handles");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Health check endpoint
async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct RegisterRequest {
    /// Handle to register (e.g., "alice@example")
    handle: String,
    /// Script pubkey in hex (the owner's taproot address script)
    script_pubkey: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    success: bool,
    message: String,
}

/// POST /register - Register a new handle
///
/// In production, you would:
/// - Validate the request (check payment, verify identity, etc.)
/// - Check if the handle is available
/// - Store the registration in a database
async fn register_handle(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    tracing::info!("Registration request for handle: {}", req.handle);

    // Basic validation
    if !req.handle.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                message: "Invalid handle format. Expected: name@space".to_string(),
            }),
        );
    }

    // Check if already registered
    {
        let registrations = state.registrations.read().await;
        if registrations.iter().any(|r| r.handle == req.handle) {
            return (
                StatusCode::CONFLICT,
                Json(RegisterResponse {
                    success: false,
                    message: "Handle already registered".to_string(),
                }),
            );
        }
    }

    // Add to pending registrations
    {
        let mut registrations = state.registrations.write().await;
        registrations.push(Registration {
            handle: req.handle.clone(),
            script_pubkey: req.script_pubkey,
            status: RegistrationStatus::Pending,
            commitment_root: None,
        });
    }

    tracing::info!("Handle {} added to pending registrations", req.handle);
    (
        StatusCode::OK,
        Json(RegisterResponse {
            success: true,
            message: format!("Handle {} has been queued for registration", req.handle),
        }),
    )
}

#[derive(Serialize)]
struct StatusResponse {
    handle: String,
    status: String,
    commitment_root: Option<String>,
}

/// GET /status/:handle - Get registration status
async fn get_status(
    State(state): State<Arc<AppState>>,
    Path(handle): Path<String>,
) -> impl IntoResponse {
    let registrations = state.registrations.read().await;

    if let Some(reg) = registrations.iter().find(|r| r.handle == handle) {
        let status_str = match reg.status {
            RegistrationStatus::Pending => "pending",
            RegistrationStatus::Staged => "staged",
            RegistrationStatus::Committed => "committed",
        };
        Json(StatusResponse {
            handle: reg.handle.clone(),
            status: status_str.to_string(),
            commitment_root: reg.commitment_root.clone(),
        })
    } else {
        Json(StatusResponse {
            handle,
            status: "not_found".to_string(),
            commitment_root: None,
        })
    }
}

// Private endpoints (for subs to call)

#[derive(Serialize)]
struct PendingHandle {
    handle: String,
    script_pubkey: String,
}

#[derive(Serialize)]
struct PendingResponse {
    handles: Vec<PendingHandle>,
}

/// GET /pending - Get pending handles for subsd to stage
///
/// subsd calls this to get handles that need to be staged.
/// In production, protect this with API key authentication.
async fn get_pending_handles(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let registrations = state.registrations.read().await;

    let pending: Vec<PendingHandle> = registrations
        .iter()
        .filter(|r| r.status == RegistrationStatus::Pending)
        .map(|r| PendingHandle {
            handle: r.handle.clone(),
            script_pubkey: r.script_pubkey.clone(),
        })
        .collect();

    tracing::info!("Returning {} pending handles", pending.len());
    Json(PendingResponse { handles: pending })
}

#[derive(Deserialize)]
struct AckRequest {
    /// Handles that were successfully staged
    handles: Vec<String>,
}

#[derive(Serialize)]
struct AckResponse {
    acknowledged: usize,
}

/// POST /ack - Acknowledge handles were staged by subsd
///
/// subsd calls this after successfully staging handles.
/// This moves them from "pending" to "staged" status.
async fn ack_handles(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AckRequest>,
) -> impl IntoResponse {
    let mut registrations = state.registrations.write().await;
    let mut count = 0;

    for handle in &req.handles {
        if let Some(reg) = registrations.iter_mut().find(|r| r.handle == *handle) {
            if reg.status == RegistrationStatus::Pending {
                reg.status = RegistrationStatus::Staged;
                count += 1;
                tracing::info!("Handle {} acknowledged as staged", handle);
            }
        }
    }

    Json(AckResponse { acknowledged: count })
}

#[derive(Deserialize)]
struct WebhookCommittedPayload {
    /// The commitment root
    root: String,
    /// Handles that were committed
    handles: Vec<String>,
}

#[derive(Serialize)]
struct WebhookResponse {
    received: bool,
    updated: usize,
}

/// POST /webhook/committed - Webhook called when handles are committed
///
/// subsd calls this after handles are committed on-chain.
/// In production, verify the webhook signature.
async fn webhook_committed(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WebhookCommittedPayload>,
) -> impl IntoResponse {
    tracing::info!(
        "Webhook: {} handles committed with root {}",
        payload.handles.len(),
        payload.root
    );

    let mut registrations = state.registrations.write().await;
    let mut count = 0;

    for handle in &payload.handles {
        if let Some(reg) = registrations.iter_mut().find(|r| r.handle == *handle) {
            reg.status = RegistrationStatus::Committed;
            reg.commitment_root = Some(payload.root.clone());
            count += 1;
            tracing::info!("Handle {} marked as committed", handle);
        }
    }

    Json(WebhookResponse {
        received: true,
        updated: count,
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}
