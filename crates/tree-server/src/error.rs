//! API errors: JSON `{code, message}` with stable codes.

use std::borrow::Cow;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: Cow<'static, str>,
    pub retry_after: Option<u64>,
    /// Extra fields merged into the JSON body (e.g. `winner_sha256`).
    pub details: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize)]
struct Body<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    details: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

impl ApiError {
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after: None,
            details: None,
        }
    }

    /// Adds a field to the JSON body.
    pub fn with(mut self, key: &str, value: serde_json::Value) -> Self {
        self.details.get_or_insert_with(Default::default).insert(key.to_owned(), value);
        self
    }

    /// `507`: the server is short of disk space.
    pub fn insufficient_storage(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::INSUFFICIENT_STORAGE, "INSUFFICIENT_STORAGE", message)
    }

    pub fn forbidden(code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    pub fn conflict(code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    pub fn unauthorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message)
    }

    pub fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message)
    }

    pub fn too_large(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE", message)
    }

    pub fn limit_exceeded(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::CONFLICT, "LIMIT_EXCEEDED", message)
    }

    pub fn rate_limited(retry_after: u64) -> Self {
        Self {
            retry_after: Some(retry_after.max(1)),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "too many requests",
            )
        }
    }

    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "internal error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = (
            self.status,
            Json(Body {
                code: self.code,
                message: &self.message,
                details: self.details.as_ref(),
            }),
        )
            .into_response();
        if let Some(secs) = self.retry_after {
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        // Database errors never carry request data (all values are bound parameters).
        tracing::error!(error = %e, "database error");
        Self::internal()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
