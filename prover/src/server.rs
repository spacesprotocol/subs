//! HTTP server mode for the prover.
//!
//! Provides a REST API for submitting proving jobs and retrieving results.
//! Jobs are processed in the background by a worker thread.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tokio::sync::{mpsc, RwLock};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::Prover;
use subs_types::{CompressInput, ProvingRequest};

/// Job status
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Processing,
    Complete,
    Failed,
}

/// Job type
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobType {
    Step,
    Fold,
    Compress,
}

/// A proving job in the queue
#[derive(Clone)]
pub struct Job {
    pub id: String,
    pub job_type: JobType,
    pub status: JobStatus,
    pub request: JobRequest,
    pub receipt: Option<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub enum JobRequest {
    Prove(ProvingRequest),
    Compress(CompressInput),
}

/// Shared server state
pub struct ServerState {
    jobs: RwLock<HashMap<String, Job>>,
    job_sender: mpsc::Sender<String>,
    /// Calibration data from startup benchmark.
    /// None if calibration hasn't run or failed.
    calibration: RwLock<Option<subs_types::CalibrationInfo>>,
}

impl ServerState {
    pub fn new(job_sender: mpsc::Sender<String>) -> Self {
        Self {
            jobs: RwLock::new(HashMap::new()),
            job_sender,
            calibration: RwLock::new(None),
        }
    }
}

/// Response for job submission
#[derive(Serialize)]
pub struct SubmitResponse {
    pub job_id: String,
    pub status: JobStatus,
}

/// Response for job status
#[derive(Serialize)]
pub struct JobStatusResponse {
    pub job_id: String,
    pub job_type: JobType,
    pub status: JobStatus,
    pub error: Option<String>,
}

/// Error response
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Start the prover server
pub async fn run_server(port: u16) -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "subs_prover=info,tower_http=debug".into()),
        )
        .init();

    // Create job channel
    let (tx, rx) = mpsc::channel::<String>(100);

    // Create shared state
    let state = Arc::new(ServerState::new(tx));

    // Calibrate proving throughput on startup
    tracing::info!("Calibrating proving throughput...");
    let calibrate_state = state.clone();
    let calibrate_handle = tokio::task::spawn_blocking(move || {
        let prover = Prover::new();
        prover.calibrate()
    });
    match calibrate_handle.await {
        Ok(Ok(info)) => {
            tracing::info!(
                "Calibration complete: {:.2}s per segment at po2={}, {:.0} cycles/sec",
                info.seconds_per_segment,
                info.calibration_po2,
                info.cycles_per_sec,
            );
            *calibrate_state.calibration.write().await = Some(info);
        }
        Ok(Err(e)) => {
            tracing::warn!("Calibration failed (estimates will be unavailable): {}", e);
        }
        Err(e) => {
            tracing::warn!("Calibration task panicked: {}", e);
        }
    }

    // Spawn the worker
    let worker_state = state.clone();
    tokio::spawn(async move {
        run_worker(worker_state, rx).await;
    });

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/prove", post(submit_prove))
        .route("/estimate", post(submit_estimate))
        .route("/compress", post(submit_compress))
        .route("/jobs/:job_id", get(get_job_status))
        .route("/jobs/:job_id/receipt", get(get_job_receipt))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Prover server starting on http://{}", addr);

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

/// Submit a proving request (binary borsh-encoded ProvingRequest)
async fn submit_prove(
    State(state): State<Arc<ServerState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Deserialize the proving request
    let request: ProvingRequest = match borsh::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid proving request: {}", e),
                }),
            )
                .into_response();
        }
    };

    let job_type = match &request {
        ProvingRequest::Step { .. } => JobType::Step,
        ProvingRequest::Fold { .. } => JobType::Fold,
    };

    // Create job
    let job_id = uuid::Uuid::new_v4().to_string();
    let job = Job {
        id: job_id.clone(),
        job_type: job_type.clone(),
        status: JobStatus::Pending,
        request: JobRequest::Prove(request),
        receipt: None,
        error: None,
    };

    // Add to queue
    {
        let mut jobs = state.jobs.write().await;
        jobs.insert(job_id.clone(), job);
    }

    // Notify worker
    if let Err(e) = state.job_sender.send(job_id.clone()).await {
        tracing::error!("Failed to queue job: {}", e);
    }

    tracing::info!("Job {} queued ({:?})", job_id, job_type);

    (
        StatusCode::ACCEPTED,
        Json(SubmitResponse {
            job_id,
            status: JobStatus::Pending,
        }),
    )
        .into_response()
}

/// Estimate cycle count and proving time for a request (binary borsh-encoded ProvingRequest)
async fn submit_estimate(
    State(state): State<Arc<ServerState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let request: ProvingRequest = match borsh::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid proving request: {}", e),
                }),
            )
                .into_response();
        }
    };

    let calibration = state.calibration.read().await.clone();

    // Execute in a blocking task since it runs the guest program
    let result = tokio::task::spawn_blocking(move || {
        let prover = Prover::new();
        prover.estimate(&request, calibration.as_ref())
    })
    .await;

    match result {
        Ok(Ok(estimate)) => (StatusCode::OK, Json(estimate)).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Estimate failed: {}", e),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Task panicked: {}", e),
            }),
        )
            .into_response(),
    }
}

/// Submit a compression request (binary borsh-encoded CompressInput)
async fn submit_compress(
    State(state): State<Arc<ServerState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Deserialize the compress input
    let input: CompressInput = match borsh::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid compress input: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Create job
    let job_id = uuid::Uuid::new_v4().to_string();
    let job = Job {
        id: job_id.clone(),
        job_type: JobType::Compress,
        status: JobStatus::Pending,
        request: JobRequest::Compress(input),
        receipt: None,
        error: None,
    };

    // Add to queue
    {
        let mut jobs = state.jobs.write().await;
        jobs.insert(job_id.clone(), job);
    }

    // Notify worker
    if let Err(e) = state.job_sender.send(job_id.clone()).await {
        tracing::error!("Failed to queue job: {}", e);
    }

    tracing::info!("Job {} queued (compress)", job_id);

    (
        StatusCode::ACCEPTED,
        Json(SubmitResponse {
            job_id,
            status: JobStatus::Pending,
        }),
    )
        .into_response()
}

/// Get job status
async fn get_job_status(
    State(state): State<Arc<ServerState>>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let jobs = state.jobs.read().await;

    match jobs.get(&job_id) {
        Some(job) => (
            StatusCode::OK,
            Json(JobStatusResponse {
                job_id: job.id.clone(),
                job_type: job.job_type.clone(),
                status: job.status.clone(),
                error: job.error.clone(),
            }),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Job not found".to_string(),
            }),
        )
            .into_response(),
    }
}

/// Get job receipt (only available when complete).
/// Removes the job after the receipt is returned so it is only pulled once.
async fn get_job_receipt(
    State(state): State<Arc<ServerState>>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    // First check status with a read lock
    {
        let jobs = state.jobs.read().await;
        match jobs.get(&job_id) {
            Some(job) if job.status != JobStatus::Complete => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Job not complete (status: {:?})", job.status),
                    }),
                )
                    .into_response();
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Job not found".to_string(),
                    }),
                )
                    .into_response();
            }
            _ => {}
        }
    }

    // Remove the job and return the receipt
    let mut jobs = state.jobs.write().await;
    match jobs.remove(&job_id) {
        Some(job) => match job.receipt {
            Some(receipt) => {
                tracing::info!("Job {} receipt pulled, removing job", job_id);
                (
                    StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "application/octet-stream",
                    )],
                    receipt,
                )
                    .into_response()
            }
            None => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Receipt not available".to_string(),
                }),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Job not found".to_string(),
            }),
        )
            .into_response(),
    }
}

/// Background worker that processes jobs
async fn run_worker(state: Arc<ServerState>, mut rx: mpsc::Receiver<String>) {
    let prover = Prover::new();

    tracing::info!("Prover worker started");

    while let Some(job_id) = rx.recv().await {
        // Get job and mark as processing
        let job_request = {
            let mut jobs = state.jobs.write().await;
            match jobs.get_mut(&job_id) {
                Some(job) => {
                    job.status = JobStatus::Processing;
                    Some(job.request.clone())
                }
                None => {
                    tracing::error!("Job {} not found", job_id);
                    None
                }
            }
        };

        let Some(request) = job_request else {
            continue;
        };

        tracing::info!("Processing job {}", job_id);

        // Execute the proof
        let result = match &request {
            JobRequest::Prove(req) => {
                let idx = req.idx();
                tracing::info!("[#{}] Starting proof...", idx);
                prover.prove(req)
            }
            JobRequest::Compress(input) => {
                tracing::info!("Starting SNARK compression...");
                prover.compress(input)
            }
        };

        // Update job with result
        {
            let mut jobs = state.jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                match result {
                    Ok(receipt) => {
                        tracing::info!("Job {} complete ({} bytes)", job_id, receipt.len());
                        job.status = JobStatus::Complete;
                        job.receipt = Some(receipt);
                    }
                    Err(e) => {
                        tracing::error!("Job {} failed: {}", job_id, e);
                        job.status = JobStatus::Failed;
                        job.error = Some(e.to_string());
                    }
                }
            }
        }
    }
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
