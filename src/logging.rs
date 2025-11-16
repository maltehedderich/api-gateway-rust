/// Logging utilities with sensitive data redaction
///
/// This module provides utilities for safely logging data while
/// automatically redacting sensitive information such as:
/// - Session tokens
/// - Authorization headers
/// - API keys
/// - Passwords
/// - Email addresses (partial)
/// - IP addresses (optional)
use regex::Regex;
use std::sync::OnceLock;

/// Placeholder for redacted values
const REDACTED: &str = "[REDACTED]";

/// Regex patterns for sensitive data
static PATTERNS: OnceLock<SensitiveDataPatterns> = OnceLock::new();

struct SensitiveDataPatterns {
    /// Pattern for Bearer tokens in Authorization headers
    bearer_token: Regex,
    /// Pattern for API keys
    api_key: Regex,
    /// Pattern for session tokens
    session_token: Regex,
    /// Pattern for passwords
    password: Regex,
    /// Pattern for email addresses
    email: Regex,
}

impl SensitiveDataPatterns {
    fn new() -> Self {
        Self {
            // Match Bearer tokens (keep first 4 chars after "Bearer ")
            bearer_token: Regex::new(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]+)")
                .expect("Invalid bearer token regex"),
            // Match API keys in query parameters, headers, or JSON
            api_key: Regex::new(r#"(?i)"?(api[_-]?key|apikey)"?\s*[:=]\s*"?([a-zA-Z0-9_\-\.]+)"?"#)
                .expect("Invalid API key regex"),
            // Match session tokens (generic token pattern)
            session_token: Regex::new(
                r#"(?i)"?(session[_-]?token|token)"?\s*[:=]\s*"?([a-zA-Z0-9_\-\.]+)"?"#,
            )
            .expect("Invalid session token regex"),
            // Match password fields
            password: Regex::new(r#"(?i)"?password"?\s*[:=]\s*"?([^",\s]+)"?"#)
                .expect("Invalid password regex"),
            // Match email addresses
            email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
                .expect("Invalid email regex"),
        }
    }
}

fn patterns() -> &'static SensitiveDataPatterns {
    PATTERNS.get_or_init(SensitiveDataPatterns::new)
}

/// Redact sensitive data from a string
///
/// This function scans the input string for common patterns of sensitive
/// data and replaces them with [REDACTED] or partially redacted values.
///
/// # Examples
///
/// ```
/// use api_gateway_rust::logging::redact_sensitive_data;
///
/// // ggshield:ignore - test fixture example
/// let input = "Authorization: Bearer abc123def456ghi789";
/// let output = redact_sensitive_data(input);
/// assert!(output.contains("Bearer abc1"));
/// assert!(output.contains("[REDACTED]"));
///
/// let input = "password=mysecretpass";
/// let output = redact_sensitive_data(input);
/// assert!(output.contains("[REDACTED]"));
/// ```
pub fn redact_sensitive_data(input: &str) -> String {
    let patterns = patterns();
    let mut result = input.to_string();

    // Redact Bearer tokens (keep first 4 chars for debugging)
    result = patterns
        .bearer_token
        .replace_all(&result, |caps: &regex::Captures| {
            let token = &caps[1];
            if token.len() > 4 {
                format!("Bearer {}...[REDACTED]", &token[..4])
            } else {
                format!("Bearer {}", REDACTED)
            }
        })
        .to_string();

    // Redact API keys completely
    result = patterns
        .api_key
        .replace_all(&result, |caps: &regex::Captures| {
            let full_match = &caps[0];
            let key_name = &caps[1];
            // Check if this looks like JSON (has quotes)
            if full_match.contains('"') {
                format!("\"{}\": \"{}\"", key_name, REDACTED)
            } else {
                format!("{}={}", key_name, REDACTED)
            }
        })
        .to_string();

    // Redact session tokens completely
    result = patterns
        .session_token
        .replace_all(&result, |caps: &regex::Captures| {
            let full_match = &caps[0];
            let key_name = &caps[1];
            // Check if this looks like JSON (has quotes)
            if full_match.contains('"') {
                format!("\"{}\": \"{}\"", key_name, REDACTED)
            } else {
                format!("{}={}", key_name, REDACTED)
            }
        })
        .to_string();

    // Redact passwords completely
    result = patterns
        .password
        .replace_all(&result, |_caps: &regex::Captures| {
            format!("\"password\": \"{}\"", REDACTED)
        })
        .to_string();

    // Redact email addresses (keep first char and domain)
    result = patterns
        .email
        .replace_all(&result, |caps: &regex::Captures| {
            let email = &caps[0];
            if let Some(at_pos) = email.find('@') {
                let local = &email[..at_pos];
                let domain = &email[at_pos..];
                if !local.is_empty() {
                    format!("{}***{}", &local[..1], domain)
                } else {
                    REDACTED.to_string()
                }
            } else {
                REDACTED.to_string()
            }
        })
        .to_string();

    result
}

/// Redact authorization header value
///
/// Specifically designed for Authorization headers.
/// Keeps the first 4 characters of the token for debugging.
pub fn redact_auth_header(value: &str) -> String {
    let patterns = patterns();
    patterns
        .bearer_token
        .replace_all(value, |caps: &regex::Captures| {
            let token = &caps[1];
            if token.len() > 4 {
                format!("Bearer {}...[REDACTED]", &token[..4])
            } else {
                format!("Bearer {}", REDACTED)
            }
        })
        .to_string()
}

/// Redact cookie value
///
/// Keeps the first 4 characters of the cookie value for debugging.
pub fn redact_cookie(value: &str) -> String {
    if value.len() > 4 {
        format!("{}...[REDACTED]", &value[..4])
    } else {
        REDACTED.to_string()
    }
}

/// Partially redact IP address
///
/// Keeps the first two octets for debugging while redacting the last two.
/// This can be useful for GDPR compliance while maintaining some debugging capability.
pub fn redact_ip_address(ip: &str) -> String {
    if let Some(second_dot) = ip.chars().enumerate().filter(|(_, c)| *c == '.').nth(1) {
        format!("{}.XXX.XXX", &ip[..second_dot.0])
    } else {
        // IPv6 or invalid format - redact completely
        "XXX.XXX.XXX.XXX".to_string()
    }
}

/// Check if a header name is sensitive and should be redacted
pub fn is_sensitive_header(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    matches!(
        name_lower.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-session-token"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_bearer_token() {
        let input = "Authorization: Bearer abc123def456ghi789";
        let output = redact_sensitive_data(input);
        assert!(output.contains("Bearer abc1"));
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("def456ghi789"));
    }

    #[test]
    fn test_redact_api_key() {
        let input = "api_key=sk_live_1234567890abcdef";
        let output = redact_sensitive_data(input);
        assert!(output.contains("api_key=[REDACTED]"));
        assert!(!output.contains("sk_live_1234567890abcdef"));
    }

    #[test]
    fn test_redact_password() {
        let input = r#"{"username": "user", "password": "secretpass123"}"#;
        let output = redact_sensitive_data(input);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("secretpass123"));
    }

    #[test]
    fn test_redact_email() {
        let input = "User email: user@example.com";
        let output = redact_sensitive_data(input);
        assert!(output.contains("u***@example.com"));
        assert!(!output.contains("user@example.com"));
    }

    #[test]
    fn test_redact_auth_header() {
        let value = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let output = redact_auth_header(value);
        assert!(output.contains("Bearer eyJh"));
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_cookie() {
        let value = "session_abc123def456";
        let output = redact_cookie(value);
        assert_eq!(output, "sess...[REDACTED]");
    }

    #[test]
    fn test_redact_ip_address() {
        let ip = "192.168.1.100";
        let output = redact_ip_address(ip);
        assert_eq!(output, "192.168.XXX.XXX");
    }

    #[test]
    fn test_is_sensitive_header() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("Cookie"));
        assert!(is_sensitive_header("X-API-Key"));
        assert!(!is_sensitive_header("Content-Type"));
        assert!(!is_sensitive_header("Accept"));
    }
}
