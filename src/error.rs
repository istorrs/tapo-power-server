//! Error type shared by the protocol client and the HTTP layer.

/// Device error codes that mean "the live session is no longer valid"; the
/// client re-handshakes once and resends.
pub const RETRYABLE_CODES: [i64; 4] = [9999, 1002, -40401, -40413];
/// Device error codes that mean the login itself was rejected. These are never
/// retried: the device counts failed attempts and locks out.
pub const AUTH_CODES: [i64; 4] = [-1501, -2202, -2203, -2101];

#[derive(Debug, thiserror::Error)]
pub enum TapoError {
    /// Caller's mistake (bad port, malformed request) -> HTTP 400.
    #[error("{0}")]
    InvalidArgument(String),
    /// The device or this implementation doesn't support it -> HTTP 501.
    #[error("{0}")]
    Unsupported(String),
    /// Login rejected, or login blocked after an earlier rejection.
    #[error("authentication failed: {0}")]
    Authentication(String),
    /// The device returned a non-zero `error_code`.
    #[error("device returned error code {code}")]
    Device { code: i64 },
    /// Malformed or unexpected protocol data.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Network-level failure (connect, reset, timeout).
    #[error("transport error: {0}")]
    Transport(String),
}

impl TapoError {
    /// Stable category name for the `error_type` field of HTTP error bodies.
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::InvalidArgument(_) => "InvalidArgument",
            Self::Unsupported(_) => "Unsupported",
            Self::Authentication(_) => "AuthenticationError",
            Self::Device { .. } => "DeviceError",
            Self::Protocol(_) => "ProtocolError",
            Self::Transport(_) => "TransportError",
        }
    }

    /// HTTP status per the pyhil contract: 400 caller mistake, 501 unsupported,
    /// 500 for anything that went wrong talking to the device.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidArgument(_) => 400,
            Self::Unsupported(_) => 501,
            _ => 500,
        }
    }

    /// Whether a fresh handshake plus one resend is appropriate.
    pub fn is_session_error(&self) -> bool {
        match self {
            Self::Device { code } => RETRYABLE_CODES.contains(code),
            Self::Transport(msg) => msg.contains("reset") || msg.contains("closed"),
            _ => false,
        }
    }
}

/// Map a non-zero device `error_code` to the right error variant.
pub fn from_device_code(code: i64, context: &str) -> TapoError {
    if AUTH_CODES.contains(&code) {
        TapoError::Authentication(format!("{context}: device error code {code}"))
    } else {
        TapoError::Device { code }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(TapoError::InvalidArgument("x".into()).http_status(), 400);
        assert_eq!(TapoError::Unsupported("x".into()).http_status(), 501);
        assert_eq!(TapoError::Device { code: -1 }.http_status(), 500);
        assert_eq!(TapoError::Transport("x".into()).http_status(), 500);
        assert_eq!(TapoError::Authentication("x".into()).http_status(), 500);
    }

    #[test]
    fn retry_classification() {
        for c in RETRYABLE_CODES {
            assert!(TapoError::Device { code: c }.is_session_error());
        }
        assert!(!TapoError::Device { code: -1010 }.is_session_error());
        assert!(!TapoError::Authentication("x".into()).is_session_error());
        assert!(!TapoError::Transport("timed out".into()).is_session_error());
        assert!(TapoError::Transport("connection reset".into()).is_session_error());
    }

    #[test]
    fn auth_codes_map_to_authentication() {
        for c in AUTH_CODES {
            assert!(matches!(
                from_device_code(c, "login"),
                TapoError::Authentication(_)
            ));
        }
        assert!(matches!(
            from_device_code(-1, "x"),
            TapoError::Device { code: -1 }
        ));
    }
}
