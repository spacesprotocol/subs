//! Shared error handling utilities for routes.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// JSON error response
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Helper to create JSON error responses
pub fn json_error(status: StatusCode, message: impl ToString) -> Response {
    (status, Json(ErrorResponse { error: message.to_string() })).into_response()
}
