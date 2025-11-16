/// Comprehensive tests for the routing module
///
/// These tests verify:
/// - Route matching with different patterns
/// - Path parameter extraction
/// - Error handling
use api_gateway_rust::routing::{PathPattern, PathTemplate, Segment};

#[test]
fn test_exact_path_match() {
    let pattern = PathPattern::parse("/api/users").unwrap();

    // Should match exact path
    assert!(pattern.matches("/api/users").is_some());

    // Should not match longer paths
    assert!(pattern.matches("/api/users/123").is_none());

    // Should not match shorter paths
    assert!(pattern.matches("/api").is_none());

    // Should not match similar paths
    assert!(pattern.matches("/api/user").is_none());
}

#[test]
fn test_exact_path_with_trailing_slash() {
    let pattern = PathPattern::parse("/api/users/").unwrap();

    // Should match exact path with trailing slash
    assert!(pattern.matches("/api/users/").is_some());

    // Should not match without trailing slash
    assert!(pattern.matches("/api/users").is_none());
}

#[test]
fn test_prefix_match_basic() {
    let pattern = PathPattern::parse("/api/*").unwrap();

    // Should match all paths starting with /api
    assert!(pattern.matches("/api/users").is_some());
    assert!(pattern.matches("/api/users/123").is_some());
    assert!(pattern.matches("/api/v1/users").is_some());
    assert!(pattern.matches("/api").is_some());

    // Should not match different prefixes
    assert!(pattern.matches("/other").is_none());
    assert!(pattern.matches("/ap").is_none());
}

#[test]
fn test_prefix_match_nested() {
    let pattern = PathPattern::parse("/api/v1/*").unwrap();

    assert!(pattern.matches("/api/v1/users").is_some());
    assert!(pattern.matches("/api/v1/users/123").is_some());
    assert!(pattern.matches("/api/v1").is_some());

    // Should not match /api/v2
    assert!(pattern.matches("/api/v2/users").is_none());
}

#[test]
fn test_template_single_parameter() {
    let pattern = PathPattern::parse("/users/{id}").unwrap();

    let result = pattern.matches("/users/123");
    assert!(result.is_some());
    let params = result.unwrap();
    assert_eq!(params.get("id"), Some(&"123".to_string()));

    let result = pattern.matches("/users/abc");
    assert!(result.is_some());
    let params = result.unwrap();
    assert_eq!(params.get("id"), Some(&"abc".to_string()));

    // Should not match with extra segments
    assert!(pattern.matches("/users/123/posts").is_none());

    // Should not match with missing segments
    assert!(pattern.matches("/users").is_none());
}

#[test]
fn test_template_multiple_parameters() {
    let pattern = PathPattern::parse("/users/{user_id}/posts/{post_id}").unwrap();

    let result = pattern.matches("/users/123/posts/456");
    assert!(result.is_some());
    let params = result.unwrap();
    assert_eq!(params.get("user_id"), Some(&"123".to_string()));
    assert_eq!(params.get("post_id"), Some(&"456".to_string()));

    // Test with different values
    let result = pattern.matches("/users/alice/posts/hello-world");
    assert!(result.is_some());
    let params = result.unwrap();
    assert_eq!(params.get("user_id"), Some(&"alice".to_string()));
    assert_eq!(params.get("post_id"), Some(&"hello-world".to_string()));
}

#[test]
fn test_template_with_literals() {
    let pattern = PathPattern::parse("/api/v1/users/{id}/profile").unwrap();

    let result = pattern.matches("/api/v1/users/123/profile");
    assert!(result.is_some());
    let params = result.unwrap();
    assert_eq!(params.get("id"), Some(&"123".to_string()));

    // Should not match if literal doesn't match
    assert!(pattern.matches("/api/v1/users/123/settings").is_none());
    assert!(pattern.matches("/api/v2/users/123/profile").is_none());
}

#[test]
fn test_path_template_parse() {
    let template = PathTemplate::parse("/users/{id}/posts/{post_id}").unwrap();

    assert_eq!(template.pattern, "/users/{id}/posts/{post_id}");
    assert_eq!(template.segments.len(), 4);

    match &template.segments[0] {
        Segment::Literal(s) => assert_eq!(s, "users"),
        _ => panic!("Expected literal segment"),
    }

    match &template.segments[1] {
        Segment::Parameter(s) => assert_eq!(s, "id"),
        _ => panic!("Expected parameter segment"),
    }
}

#[test]
fn test_path_template_empty_parameter() {
    let result = PathTemplate::parse("/users/{}/posts");
    assert!(result.is_err());
}

#[test]
fn test_path_pattern_empty() {
    let result = PathPattern::parse("");
    assert!(result.is_err());
}

// Note: Pattern priority is tested internally in the routing module
// The priority method is private, but the ordering is tested through
// route matching behavior in integration tests

#[test]
fn test_path_pattern_clone() {
    let pattern = PathPattern::parse("/users/{id}").unwrap();
    let cloned = pattern.clone();

    // Both should match the same paths
    assert!(pattern.matches("/users/123").is_some());
    assert!(cloned.matches("/users/123").is_some());
}

#[test]
fn test_template_with_special_characters() {
    let pattern = PathPattern::parse("/files/{filename}").unwrap();

    // Test with various special characters in filename
    let result = pattern.matches("/files/my-file.txt");
    assert!(result.is_some());
    assert_eq!(
        result.unwrap().get("filename"),
        Some(&"my-file.txt".to_string())
    );

    let result = pattern.matches("/files/file_123.pdf");
    assert!(result.is_some());
    assert_eq!(
        result.unwrap().get("filename"),
        Some(&"file_123.pdf".to_string())
    );
}

#[test]
fn test_root_path() {
    let pattern = PathPattern::parse("/").unwrap();

    assert!(pattern.matches("/").is_some());
    assert!(pattern.matches("/api").is_none());
}

#[test]
fn test_prefix_root() {
    let pattern = PathPattern::parse("/*").unwrap();

    // Should match any path
    assert!(pattern.matches("/").is_some());
    assert!(pattern.matches("/api").is_some());
    assert!(pattern.matches("/api/users").is_some());
}

#[test]
fn test_template_consecutive_parameters() {
    // Test with parameters next to each other (separated only by /)
    let pattern = PathPattern::parse("/api/{version}/{resource}").unwrap();

    let result = pattern.matches("/api/v1/users");
    assert!(result.is_some());
    let params = result.unwrap();
    assert_eq!(params.get("version"), Some(&"v1".to_string()));
    assert_eq!(params.get("resource"), Some(&"users".to_string()));
}

#[test]
fn test_pattern_with_numbers() {
    let pattern = PathPattern::parse("/api/v1/users").unwrap();

    assert!(pattern.matches("/api/v1/users").is_some());
    assert!(pattern.matches("/api/v2/users").is_none());
}

#[test]
fn test_prefix_no_trailing_slash() {
    let pattern = PathPattern::parse("/api/*").unwrap();

    // Should still match paths without trailing slash
    assert!(pattern.matches("/api/users").is_some());
}

#[test]
fn test_template_url_encoded_values() {
    let pattern = PathPattern::parse("/search/{query}").unwrap();

    let result = pattern.matches("/search/hello%20world");
    assert!(result.is_some());
    assert_eq!(
        result.unwrap().get("query"),
        Some(&"hello%20world".to_string())
    );
}

#[test]
fn test_segment_clone() {
    let literal = Segment::Literal("users".to_string());
    let cloned = literal.clone();

    match (literal, cloned) {
        (Segment::Literal(a), Segment::Literal(b)) => assert_eq!(a, b),
        _ => panic!("Clone didn't preserve segment type"),
    }
}

#[test]
fn test_template_leading_slash_normalization() {
    // Test that patterns are consistent with leading slash
    let pattern1 = PathPattern::parse("/users/{id}").unwrap();

    // Should match path with leading slash
    assert!(pattern1.matches("/users/123").is_some());
}

#[test]
fn test_pattern_case_sensitivity() {
    let pattern = PathPattern::parse("/api/Users").unwrap();

    // Path matching should be case-sensitive
    assert!(pattern.matches("/api/Users").is_some());
    assert!(pattern.matches("/api/users").is_none());
}

#[test]
fn test_template_multiple_slashes() {
    // Test that multiple consecutive slashes are handled
    // Note: The routing module filters out empty segments,
    // so "/api//123" becomes "/api/123" which matches
    let pattern = PathPattern::parse("/api/{id}").unwrap();

    // Should match single slash separation
    assert!(pattern.matches("/api/123").is_some());

    // Double slashes are filtered to single slashes by the split filter
    // This is acceptable behavior for a forgiving path matcher
    assert!(pattern.matches("/api//123").is_some());
}

#[test]
fn test_prefix_empty_base() {
    let pattern = PathPattern::parse("/*").unwrap();

    assert!(pattern.matches("/").is_some());
    assert!(pattern.matches("/anything").is_some());
}

#[test]
fn test_template_single_segment_param() {
    let pattern = PathPattern::parse("/{resource}").unwrap();

    let result = pattern.matches("/users");
    assert!(result.is_some());
    assert_eq!(result.unwrap().get("resource"), Some(&"users".to_string()));
}
