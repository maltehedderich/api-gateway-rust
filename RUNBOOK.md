# API Gateway Operational Runbook

This runbook provides procedures for common operational tasks and incident response for the API Gateway.

## Table of Contents

- [Quick Reference](#quick-reference)
- [Common Operational Tasks](#common-operational-tasks)
- [Incident Response](#incident-response)
- [Performance Tuning](#performance-tuning)
- [Maintenance Procedures](#maintenance-procedures)
- [Disaster Recovery](#disaster-recovery)

## Quick Reference

### Essential Commands

```bash
# Check pod status
kubectl get pods -l app=api-gateway

# View logs
kubectl logs -f -l app=api-gateway --tail=100

# Check resource usage
kubectl top pods -l app=api-gateway

# Execute shell in pod
kubectl exec -it api-gateway-<pod-id> -- /bin/bash

# Port-forward for local testing
kubectl port-forward svc/api-gateway 8080:80

# Restart deployment
kubectl rollout restart deployment/api-gateway

# Check deployment status
kubectl rollout status deployment/api-gateway

# Scale deployment
kubectl scale deployment/api-gateway --replicas=5
```

### Health Check Endpoints

- **Liveness**: `GET /health/live` - Returns 200 if process is running
- **Readiness**: `GET /health/ready` - Returns 200 if ready to serve traffic
- **Metrics**: `GET /metrics` (port 9090) - Prometheus metrics

### Important Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `http_requests_total` | Total HTTP requests | - |
| `http_request_duration_seconds` | Request latency histogram | P99 > 500ms |
| `auth_attempts_total` | Authentication attempts | Failure rate > 20% |
| `rate_limit_exceeded_total` | Rate limit denials | > 30% of requests |
| `upstream_failures_total` | Upstream service failures | > 50% failure rate |

## Common Operational Tasks

### Checking Service Health

#### Quick Health Check

```bash
# Check if pods are running
kubectl get pods -l app=api-gateway

# Check health endpoints
POD=$(kubectl get pod -l app=api-gateway -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD -- curl -s http://localhost:8080/health/live
kubectl exec $POD -- curl -s http://localhost:8080/health/ready
```

#### Detailed Health Check

```bash
# Check pod status and events
kubectl describe pods -l app=api-gateway

# Check recent logs
kubectl logs -l app=api-gateway --tail=50 --timestamps

# Check metrics
kubectl port-forward svc/api-gateway-metrics 9090:9090 &
curl http://localhost:9090/metrics | grep http_requests_total
```

### Viewing Logs

#### Real-time Logs

```bash
# All pods
kubectl logs -f -l app=api-gateway

# Specific pod
kubectl logs -f api-gateway-<pod-id>

# With timestamps
kubectl logs -f -l app=api-gateway --timestamps

# Grep for errors
kubectl logs -l app=api-gateway --tail=1000 | grep -i error
```

#### Structured Log Queries

If using structured logging with a log aggregator:

```bash
# Elasticsearch/Kibana query examples
# All errors in last hour
level:ERROR AND service:api-gateway AND @timestamp:[now-1h TO now]

# Authentication failures
event_type:auth_failure AND correlation_id:*

# Rate limit events
event_type:rate_limit_exceeded AND @timestamp:[now-15m TO now]
```

### Scaling

#### Manual Scaling

```bash
# Scale up
kubectl scale deployment/api-gateway --replicas=5

# Scale down
kubectl scale deployment/api-gateway --replicas=3

# Verify scaling
kubectl get deployment api-gateway
kubectl get pods -l app=api-gateway
```

#### Auto-Scaling

```bash
# Check HPA status
kubectl get hpa api-gateway-hpa

# Describe HPA for details
kubectl describe hpa api-gateway-hpa

# Update HPA limits
kubectl patch hpa api-gateway-hpa -p '{"spec":{"maxReplicas":15}}'
```

### Configuration Updates

#### Update ConfigMap

```bash
# Edit ConfigMap
kubectl edit configmap api-gateway-config

# Or apply updated file
kubectl apply -f k8s/configmap.yaml

# Restart pods to pick up changes
kubectl rollout restart deployment/api-gateway

# Monitor rollout
kubectl rollout status deployment/api-gateway
```

#### Update Secrets

```bash
# Create new secret (overwrites existing)
kubectl create secret generic api-gateway-secrets \
  --from-literal=jwt_secret="new-secret" \
  --namespace=default \
  --dry-run=client -o yaml | kubectl apply -f -

# Verify secret
kubectl get secret api-gateway-secrets -o yaml

# Restart pods
kubectl rollout restart deployment/api-gateway
```

#### Rollback Configuration

```bash
# View rollout history
kubectl rollout history deployment/api-gateway

# Rollback to previous version
kubectl rollout undo deployment/api-gateway

# Rollback to specific revision
kubectl rollout undo deployment/api-gateway --to-revision=2
```

### Certificate Rotation

#### Using cert-manager (Automatic)

```bash
# Check certificate status
kubectl get certificate api-gateway-tls

# Describe certificate for details
kubectl describe certificate api-gateway-tls

# Force renewal (if needed)
kubectl delete secret api-gateway-tls
# cert-manager will automatically recreate it
```

#### Manual Certificate Update

```bash
# Create TLS secret
kubectl create secret tls api-gateway-tls \
  --cert=/path/to/cert.pem \
  --key=/path/to/key.pem \
  --namespace=default \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart pods
kubectl rollout restart deployment/api-gateway
```

## Incident Response

### Incident Response Workflow

1. **Acknowledge** - Acknowledge the alert/incident
2. **Assess** - Determine severity and impact
3. **Mitigate** - Take immediate action to restore service
4. **Investigate** - Identify root cause
5. **Resolve** - Implement permanent fix
6. **Document** - Create post-mortem

### High Error Rate (5xx)

**Symptoms**: Increased 5xx error rate, alert: `APIGatewayHighErrorRate`

**Immediate Actions**:

```bash
# 1. Check pod status
kubectl get pods -l app=api-gateway

# 2. Check recent logs for errors
kubectl logs -l app=api-gateway --tail=100 | grep -i error

# 3. Check upstream service health
kubectl get pods --all-namespaces
kubectl logs -l app=<upstream-service> --tail=50

# 4. Check metrics
kubectl port-forward svc/api-gateway-metrics 9090:9090 &
curl http://localhost:9090/metrics | grep http_requests_total
curl http://localhost:9090/metrics | grep upstream_failures_total
```

**Common Causes**:

- Upstream service down or unhealthy
- Configuration error after recent deployment
- Resource exhaustion (CPU, memory)
- Database/Redis connectivity issues

**Resolution Steps**:

```bash
# If upstream service is down
kubectl get pods -l app=<upstream-service>
kubectl describe pod <upstream-pod-id>
kubectl logs <upstream-pod-id>

# If recent deployment caused issue
kubectl rollout undo deployment/api-gateway

# If resource exhaustion
kubectl top pods -l app=api-gateway
kubectl scale deployment/api-gateway --replicas=5  # Scale up

# If configuration error
kubectl get configmap api-gateway-config -o yaml
kubectl edit configmap api-gateway-config
kubectl rollout restart deployment/api-gateway
```

### High Latency

**Symptoms**: P99 latency > 500ms, alert: `APIGatewayHighLatency` or `APIGatewayVeryHighLatency`

**Immediate Actions**:

```bash
# 1. Check current latency metrics
kubectl port-forward svc/api-gateway-metrics 9090:9090 &
curl http://localhost:9090/metrics | grep http_request_duration_seconds

# 2. Check upstream latency
curl http://localhost:9090/metrics | grep upstream_request_duration_seconds

# 3. Check resource usage
kubectl top pods -l app=api-gateway

# 4. Check for slow endpoints
kubectl logs -l app=api-gateway --tail=200 | grep "latency_ms"
```

**Common Causes**:

- Slow upstream services
- High CPU/memory usage
- Database/Redis slow queries
- Network issues
- Insufficient replicas under high load

**Resolution Steps**:

```bash
# If high load
kubectl scale deployment/api-gateway --replicas=5

# If slow upstream
# Check upstream service metrics and logs
kubectl logs -l app=<upstream-service> --tail=100

# If resource constrained
# Increase resource limits
kubectl edit deployment api-gateway
# Update resources.limits.cpu and resources.limits.memory

# If Redis is slow
# Check Redis performance
kubectl exec -it <redis-pod> -- redis-cli INFO stats
kubectl exec -it <redis-pod> -- redis-cli SLOWLOG GET 10
```

### Gateway Down

**Symptoms**: All pods down, alert: `APIGatewayDown` or `APIGatewayNoReplicas`

**Immediate Actions**:

```bash
# 1. Check deployment status
kubectl get deployment api-gateway
kubectl get pods -l app=api-gateway

# 2. Describe pods for events
kubectl describe pods -l app=api-gateway

# 3. Check recent logs (including crashed containers)
kubectl logs -l app=api-gateway --previous

# 4. Check for resource issues
kubectl describe nodes
kubectl get events --sort-by='.lastTimestamp' | head -20
```

**Common Causes**:

- Invalid configuration (crashes on startup)
- Missing or invalid secrets
- Out of memory (OOMKilled)
- Node issues
- Image pull errors

**Resolution Steps**:

```bash
# If configuration error
kubectl get configmap api-gateway-config -o yaml
kubectl rollout undo deployment/api-gateway

# If missing secrets
kubectl get secret api-gateway-secrets
kubectl create secret generic api-gateway-secrets \
  --from-literal=jwt_secret="your-secret" \
  --namespace=default

# If OOMKilled
kubectl describe pod <pod-id> | grep -A 5 "Last State"
# Increase memory limits
kubectl edit deployment api-gateway

# If image pull error
kubectl describe pod <pod-id> | grep -A 10 "Events"
# Fix image name or pull secret

# If node issues
kubectl get nodes
kubectl describe node <node-name>
# Drain problematic node
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
```

### Authentication System Failures

**Symptoms**: High auth failure rate, alert: `HighAuthenticationFailureRate` or `AuthenticationSystemError`

**Immediate Actions**:

```bash
# 1. Check authentication metrics
curl http://localhost:9090/metrics | grep auth_attempts_total
curl http://localhost:9090/metrics | grep auth_failures_total

# 2. Check logs for auth errors
kubectl logs -l app=api-gateway --tail=200 | grep -i "auth"

# 3. Check JWT secret
kubectl get secret api-gateway-secrets -o yaml
```

**Common Causes**:

- JWT secret mismatch
- Session store (Redis) unavailable
- Clock skew (token expiration issues)
- Invalid token issuer/audience configuration

**Resolution Steps**:

```bash
# If session store unavailable
kubectl get pods -l app=redis
kubectl logs -l app=redis

# If JWT secret mismatch
# Verify secret is correctly set
kubectl get secret api-gateway-secrets -o jsonpath='{.data.jwt_secret}' | base64 -d

# If clock skew
# Check pod time
kubectl exec <pod-id> -- date
# Compare with actual time

# If token configuration issue
kubectl get configmap api-gateway-config -o yaml
# Verify jwt_issuer and jwt_audience match token claims
```

### Rate Limiter Failures

**Symptoms**: Rate limiting not working, alert: `RateLimiterDown`

**Immediate Actions**:

```bash
# 1. Check Redis connectivity
kubectl get pods -l app=redis
kubectl logs -l app=redis

# 2. Check rate limit metrics
curl http://localhost:9090/metrics | grep rate_limit

# 3. Check gateway logs for rate limiter errors
kubectl logs -l app=api-gateway --tail=100 | grep -i "rate"
```

**Common Causes**:

- Redis unavailable
- Redis authentication failure
- Network connectivity issues
- Rate limiting disabled in configuration

**Resolution Steps**:

```bash
# If Redis is down
kubectl get pods -l app=redis
kubectl describe pod <redis-pod-id>
kubectl logs <redis-pod-id>

# If Redis authentication failure
kubectl get secret api-gateway-secrets -o jsonpath='{.data.redis_password}' | base64 -d
# Update if incorrect

# If configuration issue
kubectl get configmap api-gateway-config -o yaml
# Verify rate_limiting section is present and correct

# Emergency: Disable rate limiting temporarily
kubectl edit configmap api-gateway-config
# Comment out rate_limiting section or set failure_mode to fail_open
kubectl rollout restart deployment/api-gateway
```

## Performance Tuning

### Resource Allocation

#### CPU and Memory

```yaml
# Conservative (low traffic)
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "250m"

# Standard (medium traffic)
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"

# High performance (high traffic)
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

Apply changes:

```bash
kubectl edit deployment api-gateway
# Update resources section
kubectl rollout status deployment/api-gateway
```

#### Replica Count

```bash
# Calculate required replicas based on traffic
# Formula: (Peak RPS / Target RPS per instance) * 1.5 (safety margin)
# Example: (10000 RPS / 2000 RPS) * 1.5 = 7.5 → 8 replicas

kubectl scale deployment/api-gateway --replicas=8
```

### Connection Pool Tuning

Edit ConfigMap to adjust connection pool settings:

```yaml
upstreams:
  - id: "user-service"
    base_url: "http://user-service:8080"
    timeout_secs: 30
    pool_max_idle_per_host: 20  # Increase for high traffic
```

### Rate Limiting Optimization

Adjust rate limits based on actual usage:

```yaml
rate_limiting:
  default_limit:
    limit: 1000
    window_secs: 3600
    algorithm: "token_bucket"
    burst_capacity: 1200  # Allow bursts
```

## Maintenance Procedures

### Planned Deployment

```bash
# 1. Notify stakeholders of maintenance window

# 2. Scale up for redundancy
kubectl scale deployment/api-gateway --replicas=5

# 3. Update configuration/image
kubectl set image deployment/api-gateway \
  api-gateway=api-gateway-rust:v1.1.0

# 4. Monitor rollout
kubectl rollout status deployment/api-gateway

# 5. Verify deployment
kubectl get pods -l app=api-gateway
kubectl logs -l app=api-gateway --tail=50

# 6. Test endpoints
curl https://api.example.com/health/ready

# 7. Monitor metrics for anomalies
# Check Grafana dashboard for 5-10 minutes

# 8. Rollback if issues detected
kubectl rollout undo deployment/api-gateway

# 9. Scale back to normal if successful
kubectl scale deployment/api-gateway --replicas=3
```

### Zero-Downtime Deployment

```bash
# Ensure rolling update strategy
kubectl get deployment api-gateway -o yaml | grep -A 5 strategy

# Should show:
# strategy:
#   type: RollingUpdate
#   rollingUpdate:
#     maxSurge: 1
#     maxUnavailable: 0

# Deploy new version
kubectl set image deployment/api-gateway \
  api-gateway=api-gateway-rust:v1.1.0

# Monitor rollout
kubectl rollout status deployment/api-gateway

# Watch pod transitions
kubectl get pods -l app=api-gateway -w
```

### Database Maintenance

If using external session store or rate limiting backend:

```bash
# 1. Notify users of potential slowdown

# 2. Switch to fail-open mode temporarily (if acceptable)
kubectl edit configmap api-gateway-config
# Set failure_mode: "fail_open" for rate limiting
kubectl rollout restart deployment/api-gateway

# 3. Perform database maintenance
# (Redis upgrade, backup, etc.)

# 4. Verify database is healthy

# 5. Switch back to fail-closed mode
kubectl edit configmap api-gateway-config
# Set failure_mode: "fail_closed"
kubectl rollout restart deployment/api-gateway

# 6. Monitor for errors
kubectl logs -l app=api-gateway --tail=100 | grep -i error
```

## Disaster Recovery

### Backup Procedures

#### Configuration Backup

```bash
# Backup all Kubernetes resources
kubectl get deployment api-gateway -o yaml > backup/deployment.yaml
kubectl get service api-gateway -o yaml > backup/service.yaml
kubectl get configmap api-gateway-config -o yaml > backup/configmap.yaml
kubectl get secret api-gateway-secrets -o yaml > backup/secrets.yaml
kubectl get hpa api-gateway-hpa -o yaml > backup/hpa.yaml

# Or backup everything
kubectl get all,cm,secret,hpa -l app=api-gateway -o yaml > backup/api-gateway-full-backup.yaml
```

#### Scheduled Backups

```bash
# Add to cron job
0 2 * * * kubectl get all,cm,secret,hpa -l app=api-gateway -o yaml > /backup/api-gateway-$(date +\%Y\%m\%d).yaml
```

### Restore Procedures

#### Full Restore

```bash
# 1. Restore secrets
kubectl apply -f backup/secrets.yaml

# 2. Restore ConfigMap
kubectl apply -f backup/configmap.yaml

# 3. Restore deployment and service
kubectl apply -f backup/deployment.yaml
kubectl apply -f backup/service.yaml

# 4. Restore HPA
kubectl apply -f backup/hpa.yaml

# 5. Verify restoration
kubectl get all -l app=api-gateway
kubectl logs -l app=api-gateway --tail=50
```

#### Recovery from Complete Failure

```bash
# 1. Verify cluster is accessible
kubectl cluster-info

# 2. Restore from backup
kubectl apply -f backup/api-gateway-full-backup.yaml

# 3. Verify pods are running
kubectl get pods -l app=api-gateway -w

# 4. Check health
POD=$(kubectl get pod -l app=api-gateway -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD -- curl -s http://localhost:8080/health/ready

# 5. Verify external access
curl https://api.example.com/health/ready

# 6. Monitor metrics
# Check Grafana dashboard

# 7. Notify stakeholders of restoration
```

### Contact Information

**On-Call Rotation**: [Link to PagerDuty/OpsGenie]

**Escalation Path**:
1. Platform Team (L1)
2. Senior SRE (L2)
3. Engineering Manager (L3)

**Related Services**:
- Upstream Services: [Contact info]
- Infrastructure Team: [Contact info]
- Database Team: [Contact info]

---

**Document Version**: 1.0
**Last Updated**: 2024-01-15
**Maintained By**: Platform Team
