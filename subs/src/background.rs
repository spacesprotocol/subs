//! Background tasks for subsd.
//!
//! Runs a proving loop that fetches estimates for pending proving requests
//! and polls user-initiated prover jobs for completion.

use std::time::Duration;
use spaces_protocol::slabel::SLabel;
use crate::state::AppState;

/// Interval between proving loop iterations when no work is found.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Interval between polls when waiting for a prover job to complete.
const JOB_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Start the background proving loop.
///
/// Iterates all operated spaces, finds pending proving requests,
/// pushes them to the configured prover, and polls for completion.
pub fn spawn_proving_loop(state: AppState) {
    tokio::spawn(async move {
        proving_loop(state).await;
    });
}

async fn proving_loop(state: AppState) {
    // Small delay to let the server finish starting
    tokio::time::sleep(Duration::from_secs(2)).await;

    loop {
        let prover_endpoint = match state.config.prover_endpoint() {
            Ok(Some(url)) => url,
            _ => {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
        };

        let spaces = state.operator.list_spaces();
        let mut did_work = false;

        for space in &spaces {
            let request = match state.operator.get_next_proving_request(space).await {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!("[{}] Error checking proving request: {}", space, e);
                    continue;
                }
            };

            did_work = true;

            let commitment_id = request.commitment_id();
            let is_fold = matches!(&request, subs_types::ProvingRequest::Fold { .. });
            let kind = if is_fold { "fold" } else { "step" };
            let job_key = format!("job:{}:{}:{}", space, commitment_id, kind);

            // Check if we already have a job in flight
            let existing_job = state.config.get(&job_key).unwrap_or(None);

            if let Some(job_id) = existing_job {
                // Poll existing in-flight jobs to completion
                match poll_job(&state, &prover_endpoint, space, &job_key, &job_id, commitment_id, is_fold).await {
                    Ok(true) => {
                        tracing::info!("[{}] Proof complete for commitment {}", space, commitment_id);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!("[{}] Poll error for job {}: {}", space, job_id, e);
                    }
                }
            } else {
                // Only fetch and store the estimate; proving is user-initiated via the UI
                if let Err(e) = fetch_and_store_estimate(&state, &prover_endpoint, space, commitment_id, &request).await {
                    tracing::debug!("[{}] Could not fetch estimate: {}", space, e);
                }
            }
        }

        let interval = if did_work { JOB_POLL_INTERVAL } else { POLL_INTERVAL };
        tokio::time::sleep(interval).await;
    }
}

/// Fetch a proving estimate from the prover and store it on the commitment.
async fn fetch_and_store_estimate(
    state: &AppState,
    prover_endpoint: &str,
    space: &SLabel,
    commitment_id: i64,
    request: &subs_types::ProvingRequest,
) -> anyhow::Result<()> {
    let request_bytes = borsh::to_vec(request)?;
    let client = reqwest::Client::new();
    let url = format!("{}/estimate", prover_endpoint.trim_end_matches('/'));

    let response = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .body(request_bytes)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("prover returned {}", response.status());
    }

    let estimate_json = response.text().await?;
    state.operator.save_estimate(space, commitment_id, &estimate_json).await?;
    tracing::info!("[{}] Estimate stored for commitment {}", space, commitment_id);
    Ok(())
}

/// Poll a prover job. Returns true if complete (success or failure).
async fn poll_job(
    state: &AppState,
    prover_endpoint: &str,
    space: &SLabel,
    job_key: &str,
    job_id: &str,
    commitment_id: i64,
    is_fold: bool,
) -> anyhow::Result<bool> {
    let client = reqwest::Client::new();
    let url = format!("{}/jobs/{}", prover_endpoint.trim_end_matches('/'), job_id);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // Job disappeared, prover may have restarted. Clean up so we re-push.
            tracing::warn!("[{}] Job {} not found on prover, will re-submit", space, job_id);
            let _ = state.config.delete(job_key);
        }
        anyhow::bail!("prover returned {}", response.status());
    }

    #[derive(serde::Deserialize)]
    struct JobStatus {
        status: String,
        error: Option<String>,
    }

    let job: JobStatus = response.json().await?;

    match job.status.as_str() {
        "complete" => {
            let receipt_url = format!("{}/jobs/{}/receipt", prover_endpoint.trim_end_matches('/'), job_id);
            let receipt_response = client.get(&receipt_url).send().await?;

            if !receipt_response.status().is_success() {
                anyhow::bail!("receipt download failed: {}", receipt_response.status());
            }

            let receipt_bytes = receipt_response.bytes().await?;

            state
                .operator
                .fulfill_request_by_id(space, commitment_id, is_fold, &receipt_bytes)
                .await?;

            let _ = state.config.delete(job_key);
            Ok(true)
        }
        "failed" => {
            let err = job.error.unwrap_or_else(|| "unknown".to_string());
            tracing::error!("[{}] Proving job {} failed: {}", space, job_id, err);
            let _ = state.config.delete(job_key);
            anyhow::bail!("prover job failed: {}", err);
        }
        _ => Ok(false),
    }
}
