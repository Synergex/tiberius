//! Authentication error and success types.

/// Auth success details, allowing the handler to override the session user.
#[derive(Debug, Clone, Default)]
pub struct AuthSuccess {
    pub session_user: Option<String>,
}

/// Authentication error that maps to a login failure.
///
/// This error type implements `std::error::Error` and can be used with
/// the standard error handling ecosystem.
#[derive(Debug, Clone)]
pub struct AuthError {
    /// SQL Server error code (e.g., 18456 for login failed).
    pub code: u32,
    /// Error state for additional context.
    pub state: u8,
    /// Error severity class (typically 14 for login errors).
    pub class: u8,
    /// Human-readable error message.
    pub message: String,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "authentication failed (error {}, state {}, class {}): {}",
            self.code, self.state, self.class, self.message
        )
    }
}

impl std::error::Error for AuthError {}

impl AuthError {
    /// Create a standard "login failed" error.
    pub fn login_failed(user: Option<&str>) -> Self {
        let message = match user {
            Some(user) if !user.is_empty() => format!("Login failed for user '{user}'."),
            _ => "Login failed.".to_string(),
        };

        Self {
            code: 18456,
            state: 1,
            class: 14,
            message,
        }
    }
}

/// Result type for authentication operations.
pub type AuthResult<T> = std::result::Result<T, AuthError>;
