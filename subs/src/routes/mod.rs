//! Route handlers for the subsd REST API.

pub mod certs;
pub mod commits;
pub mod config;
pub mod console;
mod error;
pub mod proving;
pub mod query;
pub mod registry;
pub mod requests;
pub mod status;
pub mod web;

pub use error::json_error;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

/// Build all routes for the API.
pub fn router() -> Router<AppState> {
    Router::new()
        // Web UI
        .route("/", get(web::dashboard))
        .route("/ui/operate", get(web::operate_page))
        .route("/ui/query", get(web::query_page))
        .route("/ui/settings", get(web::settings_page))
        .route("/ui/transactions", get(web::transactions_page))
        .route("/ui/spaces/:space", get(web::space_page))
        .route("/ui/spaces/:space/handles/:handle", get(web::handle_page))
        // API: Status & Spaces
        .route("/status", get(status::get_status))
        .route("/spaces", get(status::list_spaces))
        .route("/spaces/:space", get(status::get_space_status))
        .route("/spaces/:space/operate", post(status::operate_space))
        .route("/spaces/:space/handles", get(status::list_handles))
        .route("/spaces/:space/handles/:handle", get(status::get_handle))
        // API: Handle requests
        .route("/requests", post(requests::add_requests))
        .route("/requests/generate", post(requests::generate_request))
        .route("/requests/bulk-generate", post(requests::bulk_generate))
        // API: Commits & Fees
        .route("/fees", get(commits::get_fees))
        .route("/spaces/:space/commit", post(commits::commit_local))
        .route("/spaces/:space/rollback-local", post(commits::rollback_local))
        .route("/spaces/:space/park", post(commits::park_handles))
        .route("/spaces/:space/remove", post(commits::remove_handles))
        .route("/spaces/:space/broadcast", post(commits::broadcast))
        .route("/spaces/:space/commit/status", get(commits::get_commit_status))
        .route("/spaces/:space/pipeline", get(commits::get_pipeline_status))
        .route("/spaces/:space/publish", post(commits::publish_certs))
        // API: Proving
        .route("/spaces/:space/proving/next", get(proving::get_next))
        .route("/spaces/:space/proving/fulfill", post(proving::fulfill))
        .route("/spaces/:space/proving/push", post(proving::push_to_prover))
        .route("/spaces/:space/proving/poll", post(proving::poll_prover))
        .route("/spaces/:space/proving/estimate", get(proving::get_estimate))
        .route("/spaces/:space/compress", get(proving::get_compress_input))
        .route("/spaces/:space/snark", post(proving::save_snark))
        // API: Query
        .route("/query", post(query::resolve_handle))
        .route("/query/message", get(query::export_message))
        .route("/query/anchors", get(query::export_anchors))
        // API: Certificates
        .route("/certs/:handle", get(certs::issue_cert))
        // API: RPC Console
        .route("/rpc/endpoints", get(console::get_endpoints))
        .route("/rpc/spaced", post(console::proxy_spaced))
        .route("/rpc/bitcoin", post(console::proxy_bitcoin))
        .route("/rpc/mine", post(console::mine_blocks))
        // API: Configuration
        .route("/config", get(config::get_config))
        .route("/config", post(config::set_config))
        .route("/config/test/prover", post(config::test_prover))
        .route("/config/test/registry", post(config::test_registry))
        // API: Registry integration
        .route("/registry/status", get(registry::registry_status))
        .route("/registry/sync", post(registry::sync_from_registry))
        .route("/registry/notify", post(registry::notify_registry))
}
