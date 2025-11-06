//! MCP API authentication
//!
//! Provides token-based authentication for MCP server endpoints.
//! Set `DRIZZLE_API_TOKEN` environment variable to enable authentication.

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::OnceLock;

/// Cached API token from environment
static API_TOKEN: OnceLock<Option<String>> = OnceLock::new();

/// Initialize authentication from environment
///
/// Reads `DRIZZLE_API_TOKEN` environment variable.
/// If not set, authentication is disabled.
pub fn init_from_env() {
    let token = std::env::var("DRIZZLE_API_TOKEN").ok();
    if token.is_some() {
        println!("[MCP]  API authentication enabled (DRIZZLE_API_TOKEN set)");
    } else {
        println!("[MCP]  Warning: API authentication disabled (set DRIZZLE_API_TOKEN to enable)");
    }
    let _ = API_TOKEN.set(token);
}

/// Check if authentication is enabled
pub fn is_enabled() -> bool {
    API_TOKEN
        .get()
        .and_then(|opt| opt.as_ref())
        .is_some()
}

/// Axum middleware for token authentication
///
/// # Headers
/// Expects `Authorization: Bearer <token>` header
///
/// # Behavior
/// - If auth disabled: Allow all requests
/// - If auth enabled:
///   - Missing header → 401 Unauthorized
///   - Invalid token → 403 Forbidden
///   - Valid token → Continue
pub async fn auth_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    // Skip auth if not enabled
    let expected_token = match API_TOKEN.get().and_then(|opt| opt.as_ref()) {
        Some(token) => token,
        None => return Ok(next.run(request).await),
    };

    // Extract Bearer token from Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::MissingHeader)?;

    let provided_token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AuthError::InvalidFormat)?;

    // Constant-time comparison to prevent timing attacks
    if !constant_time_eq(expected_token.as_bytes(), provided_token.as_bytes()) {
        return Err(AuthError::InvalidToken);
    }

    Ok(next.run(request).await)
}

/// Authentication errors
#[derive(Debug)]
pub enum AuthError {
    MissingHeader,
    InvalidFormat,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingHeader => (
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header",
            ),
            AuthError::InvalidFormat => (
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization format (expected 'Bearer <token>')",
            ),
            AuthError::InvalidToken => (
                StatusCode::FORBIDDEN,
                "Invalid API token",
            ),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// Constant-time byte slice comparison to prevent timing attacks
///
/// Returns true if slices are equal, false otherwise.
/// Takes the same time regardless of where the first difference occurs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_auth_error_response() {
        let err = AuthError::MissingHeader;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let err = AuthError::InvalidToken;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
