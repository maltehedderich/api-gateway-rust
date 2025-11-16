use crate::config::{RouteConfig, UpstreamConfig};
use crate::error::GatewayError;
use axum::http::{Method, Uri};
use std::collections::HashMap;
use tracing::{debug, trace};

/// Router that matches incoming requests to configured routes
#[derive(Clone)]
pub struct Router {
    routes: Vec<Route>,
    #[allow(dead_code)]
    upstreams: HashMap<String, UpstreamConfig>,
}

/// Compiled route with upstream information
#[derive(Clone, Debug)]
pub struct Route {
    pub id: String,
    pub methods: Vec<Method>,
    pub pattern: PathPattern,
    pub upstream: UpstreamConfig,
    pub upstream_path: Option<String>,
    pub timeout_secs: Option<u64>,
    pub strip_prefix: Option<String>,
    pub auth_required: bool,
    pub required_roles: Vec<String>,
    pub required_permissions: Vec<String>,
}

/// Path pattern for route matching
#[derive(Clone, Debug)]
pub enum PathPattern {
    /// Exact path match
    Exact(String),
    /// Prefix match (e.g., /api/*)
    Prefix(String),
    /// Pattern with path parameters (e.g., /users/{id})
    Template(PathTemplate),
}

/// Path template with parameter extraction
#[derive(Clone, Debug)]
pub struct PathTemplate {
    pub pattern: String,
    pub segments: Vec<Segment>,
}

#[derive(Clone, Debug)]
pub enum Segment {
    Literal(String),
    Parameter(String),
}

/// Route match result
#[derive(Debug)]
pub struct RouteMatch {
    pub route: Route,
    pub path_params: HashMap<String, String>,
}

impl Router {
    /// Create a new router from configuration
    pub fn from_config(
        routes: Vec<RouteConfig>,
        upstreams: Vec<UpstreamConfig>,
    ) -> Result<Self, GatewayError> {
        // Build upstream map
        let mut upstream_map = HashMap::new();
        for upstream in upstreams {
            upstream_map.insert(upstream.id.clone(), upstream);
        }

        // Compile routes
        let mut compiled_routes = Vec::new();
        for route_config in routes {
            let upstream = upstream_map
                .get(&route_config.upstream_id)
                .ok_or_else(|| {
                    GatewayError::Config(format!(
                        "Route '{}' references unknown upstream '{}'",
                        route_config.id, route_config.upstream_id
                    ))
                })?
                .clone();

            // Parse methods
            let methods: Result<Vec<Method>, _> = route_config
                .methods
                .iter()
                .map(|m| m.parse::<Method>())
                .collect();

            let methods = methods.map_err(|e| {
                GatewayError::Config(format!("Invalid HTTP method in route '{}': {}", route_config.id, e))
            })?;

            // Parse path pattern
            let pattern = PathPattern::parse(&route_config.path)?;

            compiled_routes.push(Route {
                id: route_config.id,
                methods,
                pattern,
                upstream,
                upstream_path: route_config.upstream_path,
                timeout_secs: route_config.timeout_secs,
                strip_prefix: route_config.strip_prefix,
                auth_required: route_config.auth_required,
                required_roles: route_config.required_roles,
                required_permissions: route_config.required_permissions,
            });
        }

        // Sort routes by priority: exact > template > prefix
        compiled_routes.sort_by(|a, b| a.pattern.priority().cmp(&b.pattern.priority()));

        Ok(Self {
            routes: compiled_routes,
            upstreams: upstream_map,
        })
    }

    /// Find a matching route for the given method and URI
    pub fn find_route(&self, method: &Method, uri: &Uri) -> Option<RouteMatch> {
        let path = uri.path();
        trace!(
            method = %method,
            path = %path,
            "Matching route"
        );

        for route in &self.routes {
            // Check if method matches
            if !route.methods.contains(method) {
                continue;
            }

            // Try to match the path pattern
            if let Some(path_params) = route.pattern.matches(path) {
                debug!(
                    route_id = %route.id,
                    method = %method,
                    path = %path,
                    "Route matched"
                );

                return Some(RouteMatch {
                    route: route.clone(),
                    path_params,
                });
            }
        }

        debug!(
            method = %method,
            path = %path,
            "No route matched"
        );
        None
    }

    /// Check if a route exists for the given path (for 405 responses)
    pub fn has_route_for_path(&self, uri: &Uri) -> bool {
        let path = uri.path();
        self.routes.iter().any(|r| r.pattern.matches(path).is_some())
    }
}

impl PathPattern {
    /// Parse a path pattern from a string
    pub fn parse(pattern: &str) -> Result<Self, GatewayError> {
        if pattern.is_empty() {
            return Err(GatewayError::Config("Path pattern cannot be empty".to_string()));
        }

        // Check for prefix pattern (ends with /*)
        if pattern.ends_with("/*") {
            let prefix = pattern.trim_end_matches("/*");
            return Ok(PathPattern::Prefix(prefix.to_string()));
        }

        // Check for parameter pattern (contains {})
        if pattern.contains('{') {
            let template = PathTemplate::parse(pattern)?;
            return Ok(PathPattern::Template(template));
        }

        // Otherwise, it's an exact match
        Ok(PathPattern::Exact(pattern.to_string()))
    }

    /// Match the pattern against a path, returning parameters if matched
    pub fn matches(&self, path: &str) -> Option<HashMap<String, String>> {
        match self {
            PathPattern::Exact(exact) => {
                if path == exact {
                    Some(HashMap::new())
                } else {
                    None
                }
            }
            PathPattern::Prefix(prefix) => {
                if path.starts_with(prefix) {
                    Some(HashMap::new())
                } else {
                    None
                }
            }
            PathPattern::Template(template) => template.matches(path),
        }
    }

    /// Get priority for sorting (lower is higher priority)
    fn priority(&self) -> u8 {
        match self {
            PathPattern::Exact(_) => 0,      // Highest priority
            PathPattern::Template(_) => 1,   // Medium priority
            PathPattern::Prefix(_) => 2,     // Lowest priority
        }
    }
}

impl PathTemplate {
    /// Parse a path template with parameters
    pub fn parse(pattern: &str) -> Result<Self, GatewayError> {
        let mut segments = Vec::new();
        let parts: Vec<&str> = pattern.split('/').collect();

        for part in parts {
            if part.is_empty() {
                continue;
            }

            if part.starts_with('{') && part.ends_with('}') {
                // Parameter segment
                let param_name = part.trim_start_matches('{').trim_end_matches('}');
                if param_name.is_empty() {
                    return Err(GatewayError::Config(
                        "Empty parameter name in path pattern".to_string(),
                    ));
                }
                segments.push(Segment::Parameter(param_name.to_string()));
            } else {
                // Literal segment
                segments.push(Segment::Literal(part.to_string()));
            }
        }

        Ok(PathTemplate {
            pattern: pattern.to_string(),
            segments,
        })
    }

    /// Match the template against a path, extracting parameters
    pub fn matches(&self, path: &str) -> Option<HashMap<String, String>> {
        let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if path_parts.len() != self.segments.len() {
            return None;
        }

        let mut params = HashMap::new();

        for (i, segment) in self.segments.iter().enumerate() {
            match segment {
                Segment::Literal(literal) => {
                    if path_parts[i] != literal {
                        return None;
                    }
                }
                Segment::Parameter(name) => {
                    params.insert(name.clone(), path_parts[i].to_string());
                }
            }
        }

        Some(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pattern = PathPattern::parse("/api/users").unwrap();
        assert!(pattern.matches("/api/users").is_some());
        assert!(pattern.matches("/api/users/123").is_none());
        assert!(pattern.matches("/api").is_none());
    }

    #[test]
    fn test_prefix_match() {
        let pattern = PathPattern::parse("/api/*").unwrap();
        assert!(pattern.matches("/api/users").is_some());
        assert!(pattern.matches("/api/users/123").is_some());
        assert!(pattern.matches("/api").is_some());
        assert!(pattern.matches("/other").is_none());
    }

    #[test]
    fn test_template_match() {
        let pattern = PathPattern::parse("/users/{id}").unwrap();
        let result = pattern.matches("/users/123");
        assert!(result.is_some());
        let params = result.unwrap();
        assert_eq!(params.get("id"), Some(&"123".to_string()));

        assert!(pattern.matches("/users/123/posts").is_none());
        assert!(pattern.matches("/users").is_none());
    }

    #[test]
    fn test_template_multiple_params() {
        let pattern = PathPattern::parse("/users/{user_id}/posts/{post_id}").unwrap();
        let result = pattern.matches("/users/123/posts/456");
        assert!(result.is_some());
        let params = result.unwrap();
        assert_eq!(params.get("user_id"), Some(&"123".to_string()));
        assert_eq!(params.get("post_id"), Some(&"456".to_string()));
    }

    #[test]
    fn test_pattern_priority() {
        let exact = PathPattern::parse("/api/users").unwrap();
        let template = PathPattern::parse("/api/{resource}").unwrap();
        let prefix = PathPattern::parse("/api/*").unwrap();

        assert!(exact.priority() < template.priority());
        assert!(template.priority() < prefix.priority());
    }
}
