# Operational Readiness Guide

This document provides comprehensive guidelines for operating the API Gateway in production environments, including incident response procedures, capacity planning, backup and recovery strategies, and operational best practices.

## Table of Contents

- [1. Logging Aggregation](#1-logging-aggregation)
- [2. Incident Response Plan](#2-incident-response-plan)
- [3. Capacity Planning](#3-capacity-planning)
- [4. Backup and Recovery](#4-backup-and-recovery)
- [5. Monitoring and Alerting](#5-monitoring-and-alerting)
- [6. Operational Runbooks](#6-operational-runbooks)

---

## 1. Logging Aggregation

### 1.1 Overview

The API Gateway supports multiple centralized logging backends for production-grade log aggregation, analysis, and long-term retention.

### 1.2 Supported Log Aggregation Systems

#### 1.2.1 Elasticsearch

**Configuration Example:**

```yaml
logging:
  level: INFO
  format: json
  structured: true
  redaction_enabled: true
  sampling_rate: 1.0
  sinks:
    - type: elasticsearch
      enabled: true
      min_level: INFO
      elasticsearch:
        urls:
          - "https://elasticsearch.example.com:9200"
        index: "api-gateway-logs-%Y.%m.%d"
        batch_size: 100
        flush_interval_secs: 5
        username: "gateway_logger"
        password: "${ELASTICSEARCH_PASSWORD}"
```

**Features:**
- Daily index rotation for efficient storage management
- Bulk indexing for high throughput
- Automatic batching and buffering
- Authentication support

**Best Practices:**
- Use index lifecycle management (ILM) to automatically delete old indices
- Configure appropriate shard count based on log volume
- Use index templates for consistent mapping
- Monitor Elasticsearch cluster health

#### 1.2.2 AWS CloudWatch Logs

**Configuration Example:**

```yaml
logging:
  level: INFO
  format: json
  structured: true
  sinks:
    - type: cloudwatch
      enabled: true
      cloudwatch:
        region: "us-east-1"
        log_group: "/aws/api-gateway/production"
        log_stream: "gateway-{instance_id}"
        batch_size: 100
        flush_interval_secs: 5
```

**Environment Variables:**
```bash
AWS_ACCESS_KEY_ID=<access_key>
AWS_SECRET_ACCESS_KEY=<secret_key>
AWS_REGION=us-east-1
```

**Features:**
- Integration with AWS ecosystem (CloudWatch Insights, Alarms)
- Automatic log group and stream creation
- Template support for dynamic stream naming
- IAM-based access control

**Best Practices:**
- Use IAM roles instead of access keys when running on EC2/ECS/EKS
- Configure log retention policies to manage costs
- Use CloudWatch Insights for log analysis
- Set up metric filters for important events

#### 1.2.3 Splunk

**Configuration Example:**

```yaml
logging:
  level: INFO
  format: json
  structured: true
  sinks:
    - type: splunk
      enabled: true
      splunk:
        endpoint: "https://splunk.example.com:8088/services/collector"
        token: "${SPLUNK_HEC_TOKEN}"
        sourcetype: "api_gateway"
        index: "production"
        batch_size: 100
        flush_interval_secs: 5
```

**Features:**
- HTTP Event Collector (HEC) protocol
- Batched event submission
- Custom source types and indices
- Metadata enrichment

**Best Practices:**
- Use dedicated HEC token per environment
- Configure appropriate source types for parsing
- Monitor HEC endpoint health
- Use Splunk apps for API gateway analytics

#### 1.2.4 File Logging with Rotation

**Configuration Example:**

```yaml
logging:
  level: INFO
  format: json
  structured: true
  sinks:
    - type: file
      enabled: true
      file:
        path: "/var/log/api-gateway/gateway.log"
        rotation_enabled: true
        max_size_mb: 100
        max_backups: 10
        max_age_days: 30
```

**Features:**
- Size-based rotation
- Time-based retention
- Compressed archived logs
- Automatic cleanup

**Best Practices:**
- Use external log shippers (Filebeat, Fluentd) for centralization
- Monitor disk space usage
- Configure appropriate rotation policies
- Ensure log directory has sufficient IOPS

### 1.3 Multi-Sink Configuration

You can configure multiple log sinks simultaneously:

```yaml
logging:
  level: INFO
  format: json
  structured: true
  redaction_enabled: true
  sinks:
    # Stdout for container logs
    - type: stdout
      enabled: true
      min_level: INFO

    # Elasticsearch for long-term storage
    - type: elasticsearch
      enabled: true
      min_level: INFO
      elasticsearch:
        urls: ["https://elasticsearch.example.com:9200"]
        index: "api-gateway-logs-%Y.%m.%d"

    # File for local debugging
    - type: file
      enabled: true
      min_level: DEBUG
      file:
        path: "/var/log/api-gateway/debug.log"
        rotation_enabled: true
        max_size_mb: 50
        max_backups: 5
```

### 1.4 Log Format and Structure

All logs follow a consistent JSON structure:

```json
{
  "timestamp": "2024-03-15T12:34:56.789Z",
  "level": "INFO",
  "service": "api-gateway",
  "component": "auth",
  "event_type": "request_received",
  "correlation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "message": "Request received",
  "method": "GET",
  "path": "/api/users",
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "request_size": 0
}
```

### 1.5 Sensitive Data Redaction

The gateway automatically redacts sensitive information:

- **Session tokens**: Only first 4 characters shown
- **Authorization headers**: Bearer tokens partially masked
- **API keys**: Completely redacted
- **Passwords**: Completely redacted
- **Email addresses**: Partially masked (first character + domain)

**Configuration:**

```yaml
logging:
  redaction_enabled: true
```

### 1.6 Log Sampling

For high-volume environments, configure log sampling:

```yaml
logging:
  sampling_rate: 0.1  # Log 10% of successful requests
```

**Recommended Sampling Strategy:**
- Error logs (4xx, 5xx): Always log (100%)
- Successful requests (2xx, 3xx): Sample based on volume
- Health check requests: Sample heavily or exclude
- Authentication failures: Always log

---

## 2. Incident Response Plan

### 2.1 Overview

This section defines procedures for responding to incidents affecting the API Gateway's availability, performance, or security.

### 2.2 Incident Severity Levels

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| **SEV1 - Critical** | Complete service outage | 15 minutes | Gateway down, all requests failing |
| **SEV2 - High** | Partial outage or severe degradation | 1 hour | High error rate (>50%), severe latency |
| **SEV3 - Medium** | Minor degradation | 4 hours | Moderate error rate (10-50%), elevated latency |
| **SEV4 - Low** | Minimal impact | 1 business day | Single instance issues, non-critical features |

### 2.3 Incident Response Team Roles

#### 2.3.1 Incident Commander (IC)
- **Responsibilities:**
  - Coordinate incident response
  - Make escalation decisions
  - Ensure communication
  - Declare incident resolved
- **Contact:** On-call rotation via PagerDuty/Opsgenie

#### 2.3.2 Technical Lead
- **Responsibilities:**
  - Diagnose root cause
  - Implement fixes
  - Coordinate with infrastructure team
- **Contact:** Engineering team lead

#### 2.3.3 Communications Lead
- **Responsibilities:**
  - Update status page
  - Notify stakeholders
  - Prepare incident reports
- **Contact:** Product/Operations manager

### 2.4 Incident Response Procedures

#### 2.4.1 Detection

**Automated Detection:**
- Prometheus alerts trigger PagerDuty
- Health check failures detected by load balancer
- High error rate alerts
- Latency threshold violations

**Manual Detection:**
- Customer reports
- Internal testing
- Monitoring dashboard anomalies

#### 2.4.2 Initial Response (First 15 Minutes)

1. **Acknowledge the incident** in paging system
2. **Assess severity** using criteria above
3. **Create incident channel** (Slack: #incident-YYYYMMDD-NNN)
4. **Page additional responders** if SEV1/SEV2
5. **Update status page** if customer-facing impact

#### 2.4.3 Investigation and Diagnosis

**Check Gateway Health:**

```bash
# Check pod status
kubectl get pods -l app=api-gateway -n production

# Check recent events
kubectl get events -n production --sort-by=.lastTimestamp | tail -20

# Check logs for errors
kubectl logs -l app=api-gateway -n production --tail=100 | grep ERROR
```

**Check Metrics:**

```bash
# Port-forward to metrics endpoint
kubectl port-forward -n production svc/api-gateway-metrics 9090:9090

# Query critical metrics
curl http://localhost:9090/metrics | grep -E "(http_requests_total|error_rate|latency)"
```

**Common Issues and Diagnostics:**

| Symptom | Possible Cause | Diagnostic Commands |
|---------|----------------|---------------------|
| All requests failing | Gateway pods down | `kubectl get pods -l app=api-gateway` |
| High latency | Upstream service slow | Check `upstream_request_duration_seconds` |
| Authentication failures | Redis/session store down | `kubectl logs` for auth errors |
| Rate limiting errors | Redis connection issues | Check rate limiter logs |
| 502/504 errors | Upstream service unreachable | Check upstream health |

#### 2.4.4 Mitigation and Resolution

**SEV1 - Critical Outage:**

1. **Immediate Actions:**
   ```bash
   # Restart gateway pods
   kubectl rollout restart deployment/api-gateway -n production

   # Scale up replicas temporarily
   kubectl scale deployment/api-gateway --replicas=10 -n production

   # Rollback to previous version if needed
   kubectl rollout undo deployment/api-gateway -n production
   ```

2. **Verify Resolution:**
   ```bash
   # Check rollout status
   kubectl rollout status deployment/api-gateway -n production

   # Test health endpoints
   curl https://api.example.com/health/ready

   # Check error rate
   watch -n 5 'curl -s http://localhost:9090/metrics | grep http_requests_total'
   ```

**SEV2 - Partial Outage:**

1. **Identify Affected Routes:**
   ```bash
   # Check metrics by route
   curl http://localhost:9090/metrics | grep http_requests_total | grep 'status="5'
   ```

2. **Isolate Issue:**
   - Check specific upstream health
   - Review recent configuration changes
   - Check rate limit settings

3. **Apply Targeted Fix:**
   - Update route configuration
   - Adjust rate limits
   - Fix upstream connectivity

#### 2.4.5 Communication Templates

**Initial Notification (Status Page):**

```
Title: [INVESTIGATING] API Gateway Issues
Status: Investigating
Impact: High error rates on API requests

We are currently investigating elevated error rates affecting API
requests. Our team is actively working to identify and resolve
the issue.

Updates will be provided every 15 minutes.
```

**Resolution Notification:**

```
Title: [RESOLVED] API Gateway Issues
Status: Resolved
Impact: Issue resolved, services operating normally

The API Gateway issue has been resolved. All services are
operating normally. A post-mortem will be published within
48 hours.

Root Cause: [Brief summary]
Resolution: [Brief summary of fix]
```

### 2.5 Escalation Paths

**Level 1: On-Call Engineer**
- Initial response
- Basic troubleshooting
- Escalates if not resolved in 30 minutes (SEV1) or 2 hours (SEV2)

**Level 2: Engineering Lead**
- Complex technical issues
- Configuration changes requiring approval
- Escalates to CTO for business decisions

**Level 3: CTO/VP Engineering**
- Major infrastructure decisions
- External vendor engagement
- Executive communication

### 2.6 Post-Incident Review

**Timeline:**
- Schedule post-mortem within 48 hours of resolution
- Publish report within 1 week

**Report Template:**

```markdown
# Incident Post-Mortem: [Incident Title]

**Date:** YYYY-MM-DD
**Severity:** SEV1/SEV2/SEV3
**Duration:** X hours Y minutes
**Impact:** [Description of customer impact]

## Timeline

- HH:MM - [Event description]
- HH:MM - [Action taken]

## Root Cause

[Detailed explanation of what caused the incident]

## Resolution

[Detailed explanation of how the incident was resolved]

## Action Items

1. [ ] [Preventive measure] - Assigned to: [Name] - Due: [Date]
2. [ ] [System improvement] - Assigned to: [Name] - Due: [Date]
3. [ ] [Documentation update] - Assigned to: [Name] - Due: [Date]

## Lessons Learned

- [Lesson 1]
- [Lesson 2]
```

---

## 3. Capacity Planning

### 3.1 Performance Baselines

**Target Metrics:**
- **Throughput:** >10,000 requests/second per instance
- **Latency:** P99 < 500ms (gateway overhead < 10ms)
- **Error Rate:** < 0.1% under normal load
- **Availability:** 99.99% uptime (4.38 minutes downtime/month)

### 3.2 Resource Requirements

#### 3.2.1 Single Instance Resources

**Minimum Requirements:**
- **CPU:** 1 core
- **Memory:** 512 MB
- **Network:** 1 Gbps

**Recommended for Production:**
- **CPU:** 2-4 cores
- **Memory:** 2-4 GB
- **Network:** 10 Gbps

**Resource Limits (Kubernetes):**

```yaml
resources:
  requests:
    cpu: 1000m
    memory: 2Gi
  limits:
    cpu: 2000m
    memory: 4Gi
```

#### 3.2.2 Capacity Calculation

**Formula:**

```
Required Instances = (Peak RPS / Target RPS per Instance) * Safety Factor
```

**Example Calculation:**

```
Given:
- Peak Traffic: 100,000 requests/second
- Target per Instance: 10,000 req/sec
- Safety Factor: 1.5 (for overhead and failover)

Required Instances = (100,000 / 10,000) * 1.5 = 15 instances
```

**Recommended Safety Factors:**
- **Normal Operations:** 1.5x (50% overhead)
- **High Availability:** 2.0x (N+1 redundancy)
- **Peak Events:** 3.0x (handles 3x traffic spike)

### 3.3 Scaling Strategies

#### 3.3.1 Horizontal Pod Autoscaling (HPA)

**Configuration:**

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway-hpa
  namespace: production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: 8000
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
```

**Key Parameters:**
- **minReplicas:** Always-on baseline (handles minimum traffic + failover)
- **maxReplicas:** Maximum scale (cost control)
- **CPU threshold:** 70% (allows headroom for spikes)
- **Scale-up:** Aggressive (double capacity every 30s if needed)
- **Scale-down:** Conservative (reduce by 50% every 60s max)

#### 3.3.2 Vertical Pod Autoscaling (VPA)

**Use Case:** Right-size pod resources over time

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: api-gateway-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: api-gateway
      minAllowed:
        cpu: 500m
        memory: 1Gi
      maxAllowed:
        cpu: 4000m
        memory: 8Gi
```

### 3.4 Dependency Capacity Planning

#### 3.4.1 Redis (Rate Limiting & Sessions)

**Capacity Requirements:**

```
Memory Calculation:
- Session Storage: [Active Sessions] * [Session Size]
- Rate Limit Counters: [Unique Keys] * [Counter Size]

Example:
- 100,000 active sessions * 1 KB = 100 MB
- 1,000,000 rate limit keys * 100 bytes = 100 MB
Total: ~200 MB + 50% overhead = 300 MB
```

**Recommended Setup:**
- **Instance Type:** Redis Cluster (for high availability)
- **Memory:** 2-4 GB minimum
- **Persistence:** AOF for session data
- **Replication:** Master + 2 replicas minimum
- **Connection Pool:** 10 connections per gateway instance

**Redis Scaling:**

```bash
# Monitor Redis memory usage
redis-cli INFO memory

# Monitor connection count
redis-cli INFO clients

# Monitor operations/second
redis-cli INFO stats | grep instantaneous_ops_per_sec
```

#### 3.4.2 Upstream Services

**Connection Pool Sizing:**

```
Pool Size per Upstream = (Gateway Instances * Max Concurrent Requests per Instance) / Upstream Instances

Example:
- 10 gateway instances
- 100 max concurrent requests per instance
- 5 upstream instances

Pool Size = (10 * 100) / 5 = 200 connections per upstream instance
```

**Recommendation:** Configure upstream connection pools:

```yaml
upstreams:
  - id: user-service
    base_url: http://user-service:8080
    pool_max_idle_per_host: 50
    timeout_secs: 30
```

### 3.5 Traffic Projections

**Growth Planning:**

| Metric | Current | 6 Months | 12 Months | Notes |
|--------|---------|----------|-----------|-------|
| Peak RPS | 10,000 | 20,000 | 40,000 | Expected 100% YoY growth |
| Avg RPS | 5,000 | 10,000 | 20,000 | |
| Active Users | 100,000 | 200,000 | 400,000 | |
| Required Instances | 3 | 6 | 12 | Min replicas based on peak |
| Redis Memory | 500 MB | 1 GB | 2 GB | Session + rate limit storage |

**Review Schedule:**
- **Monthly:** Review actual vs. projected traffic
- **Quarterly:** Adjust capacity plans and budgets
- **Annually:** Major architecture review

### 3.6 Cost Optimization

#### 3.6.1 Right-Sizing

**Actions:**
- Use VPA to identify over-provisioned resources
- Review CPU/memory utilization weekly
- Scale down non-production environments during off-hours

#### 3.6.2 Efficient Scaling

**Strategies:**
- Use cluster autoscaler for node-level scaling
- Configure pod disruption budgets to prevent over-scaling
- Use preemptible/spot instances for non-critical environments

**Example PodDisruptionBudget:**

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: api-gateway-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: api-gateway
```

### 3.7 Load Testing

**Regular Testing Schedule:**
- **Weekly:** Smoke tests (baseline verification)
- **Monthly:** Load tests (capacity verification)
- **Quarterly:** Stress tests (breaking point identification)
- **Pre-Launch:** Spike tests (traffic surge preparation)

**Load Test Scenarios:**

```bash
# Baseline test - normal load
./load-test.sh --rps 5000 --duration 10m

# Capacity test - 2x peak load
./load-test.sh --rps 20000 --duration 30m

# Stress test - find breaking point
./load-test.sh --rps-start 1000 --rps-max 50000 --ramp-up 5m

# Spike test - sudden traffic increase
./load-test.sh --rps 5000 --spike-rps 25000 --spike-duration 2m
```

**Success Criteria:**
- P99 latency < 500ms at target RPS
- Error rate < 0.1%
- No pod restarts or OOM kills
- Autoscaling responds within 2 minutes

---

## 4. Backup and Recovery

### 4.1 Configuration Backup

#### 4.1.1 Version Control

**Primary Backup Method:**
- All configuration files in Git repository
- Configuration changes via pull requests
- Tag releases for rollback capability

**Repository Structure:**

```
config/
├── production/
│   ├── config.yaml
│   ├── routes.yaml
│   └── secrets/ (encrypted)
├── staging/
│   └── config.yaml
└── development/
    └── config.yaml
```

#### 4.1.2 Automated Backups

**Backup Configuration to S3/GCS:**

```bash
#!/bin/bash
# backup-config.sh

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/tmp/config-backup-${TIMESTAMP}"

# Export current configuration
kubectl get configmap api-gateway-config -n production -o yaml > ${BACKUP_DIR}/configmap.yaml
kubectl get secret api-gateway-secrets -n production -o yaml > ${BACKUP_DIR}/secrets.yaml

# Upload to S3
aws s3 cp ${BACKUP_DIR}/ s3://backups/api-gateway/${TIMESTAMP}/ --recursive

# Cleanup
rm -rf ${BACKUP_DIR}
```

**Schedule:** Daily via cron/Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: config-backup
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: api-gateway-backup:latest
            command: ["/scripts/backup-config.sh"]
          restartPolicy: OnFailure
```

### 4.2 State Backup (Redis)

#### 4.2.1 Redis Persistence

**Configuration:**

```conf
# redis.conf

# RDB Snapshot
save 900 1      # Save if 1 key changed in 15 minutes
save 300 10     # Save if 10 keys changed in 5 minutes
save 60 10000   # Save if 10,000 keys changed in 1 minute

# AOF (Append-Only File)
appendonly yes
appendfsync everysec  # Fsync every second
```

**Backup RDB Files:**

```bash
#!/bin/bash
# backup-redis.sh

REDIS_HOST="redis-master.production.svc.cluster.local"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Trigger BGSAVE
redis-cli -h ${REDIS_HOST} BGSAVE

# Wait for save to complete
while [ $(redis-cli -h ${REDIS_HOST} LASTSAVE) -eq $LASTSAVE ]; do
  sleep 1
done

# Copy RDB file
kubectl cp production/redis-master-0:/data/dump.rdb /tmp/redis-backup-${TIMESTAMP}.rdb

# Upload to S3
aws s3 cp /tmp/redis-backup-${TIMESTAMP}.rdb s3://backups/redis/
```

**Schedule:** Every 6 hours

#### 4.2.2 Redis Replication

**High Availability Setup:**

```yaml
# Redis master
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-master
spec:
  serviceName: redis
  replicas: 1
  template:
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        volumeMounts:
        - name: data
          mountPath: /data

---
# Redis replicas
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-replica
spec:
  serviceName: redis-replica
  replicas: 2
  template:
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
        - redis-server
        - --replicaof
        - redis-master-0.redis
        - "6379"
```

### 4.3 Disaster Recovery Procedures

#### 4.3.1 Recovery Time Objective (RTO) and Recovery Point Objective (RPO)

| Component | RPO | RTO | Backup Frequency |
|-----------|-----|-----|------------------|
| Gateway Configuration | 0 (Git) | 5 minutes | Real-time (Git) |
| Redis Session Data | 1 hour | 15 minutes | Hourly snapshots |
| Redis Rate Limit Data | Acceptable loss | 15 minutes | Can rebuild |
| Logs | 5 minutes | N/A | Real-time streaming |

#### 4.3.2 Configuration Recovery

**Scenario:** Configuration file corrupted or deleted

```bash
# 1. Restore from Git
git checkout production/config.yaml

# 2. Apply to cluster
kubectl create configmap api-gateway-config \
  --from-file=config.yaml=config.yaml \
  -n production \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Restart pods to pick up new config
kubectl rollout restart deployment/api-gateway -n production

# 4. Verify
kubectl logs -l app=api-gateway -n production | grep "Configuration loaded"
```

**Time to Recovery:** < 5 minutes

#### 4.3.3 Redis Recovery

**Scenario:** Redis data loss

```bash
# 1. Stop gateway (to prevent writes during recovery)
kubectl scale deployment/api-gateway --replicas=0 -n production

# 2. Download latest backup
aws s3 cp s3://backups/redis/redis-backup-latest.rdb /tmp/dump.rdb

# 3. Copy to Redis pod
kubectl cp /tmp/dump.rdb production/redis-master-0:/data/dump.rdb

# 4. Restart Redis
kubectl delete pod redis-master-0 -n production

# 5. Wait for Redis to start
kubectl wait --for=condition=ready pod/redis-master-0 -n production --timeout=60s

# 6. Verify data
redis-cli -h redis-master.production.svc.cluster.local DBSIZE

# 7. Restart gateway
kubectl scale deployment/api-gateway --replicas=10 -n production
```

**Time to Recovery:** 10-15 minutes

#### 4.3.4 Complete Cluster Failure

**Scenario:** Entire Kubernetes cluster lost

```bash
# 1. Provision new cluster
# (Infrastructure as Code - Terraform/Pulumi)

# 2. Restore configuration
git clone https://github.com/org/api-gateway-config.git
cd api-gateway-config/production

# 3. Apply Kubernetes resources
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# 4. Restore Redis
# Follow Redis recovery procedure above

# 5. Verify health
kubectl get pods -n production
curl https://api.example.com/health/ready

# 6. Update DNS/Load balancer to point to new cluster
```

**Time to Recovery:** 30-60 minutes (depends on infrastructure provisioning)

### 4.4 Backup Testing

**Test Schedule:**
- **Monthly:** Restore configuration from backup
- **Quarterly:** Full disaster recovery drill
- **Annually:** Complete cluster rebuild test

**Test Procedure:**

```bash
#!/bin/bash
# test-recovery.sh

set -e

echo "Starting DR test..."

# 1. Create test namespace
kubectl create namespace dr-test

# 2. Restore configuration
kubectl apply -f backup/configmap.yaml -n dr-test

# 3. Deploy gateway
kubectl apply -f k8s/deployment.yaml -n dr-test

# 4. Wait for ready
kubectl wait --for=condition=ready pod -l app=api-gateway -n dr-test --timeout=120s

# 5. Test functionality
POD=$(kubectl get pod -l app=api-gateway -n dr-test -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n dr-test ${POD} -- curl -s http://localhost:8080/health/live

# 6. Cleanup
kubectl delete namespace dr-test

echo "DR test successful!"
```

### 4.5 Backup Retention Policy

| Backup Type | Retention Period | Storage Location |
|-------------|------------------|------------------|
| Configuration (Git) | Indefinite | GitHub/GitLab |
| Daily Config Snapshots | 30 days | S3/GCS |
| Hourly Redis Snapshots | 7 days | S3/GCS |
| Daily Redis Snapshots | 30 days | S3/GCS |
| Monthly Redis Snapshots | 1 year | S3 Glacier/Archive |
| Log Archives | 90 days | Elasticsearch/S3 |

---

## 5. Monitoring and Alerting

### 5.1 Critical Alerts

**Configure these alerts in Prometheus/Alertmanager:**

#### 5.1.1 Availability Alerts

```yaml
# alerts/availability.yaml

groups:
- name: availability
  interval: 30s
  rules:

  # Gateway pods down
  - alert: GatewayPodsDown
    expr: kube_deployment_status_replicas_available{deployment="api-gateway"} < 2
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "API Gateway has fewer than 2 pods available"
      description: "Only {{ $value }} pod(s) available"

  # High error rate
  - alert: HighErrorRate
    expr: |
      sum(rate(http_requests_total{status=~"5.."}[5m]))
      / sum(rate(http_requests_total[5m])) > 0.05
    for: 3m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value | humanizePercentage }}"

  # Health check failures
  - alert: HealthCheckFailing
    expr: up{job="api-gateway"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "API Gateway health check failing"
```

#### 5.1.2 Performance Alerts

```yaml
# alerts/performance.yaml

groups:
- name: performance
  interval: 30s
  rules:

  # High latency
  - alert: HighLatency
    expr: |
      histogram_quantile(0.99,
        rate(http_request_duration_seconds_bucket[5m])
      ) > 0.5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "P99 latency above threshold"
      description: "P99 latency is {{ $value }}s"

  # High CPU usage
  - alert: HighCPU
    expr: |
      avg(rate(container_cpu_usage_seconds_total{
        pod=~"api-gateway-.*"
      }[5m])) > 0.8
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage on gateway pods"

  # High memory usage
  - alert: HighMemory
    expr: |
      avg(container_memory_usage_bytes{pod=~"api-gateway-.*"}
        / container_spec_memory_limit_bytes) > 0.9
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage on gateway pods"
```

#### 5.1.3 Dependency Alerts

```yaml
# alerts/dependencies.yaml

groups:
- name: dependencies
  interval: 30s
  rules:

  # Redis down
  - alert: RedisDown
    expr: up{job="redis"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Redis is down"

  # High upstream errors
  - alert: UpstreamErrors
    expr: |
      sum(rate(upstream_failures_total[5m])) by (service) > 10
    for: 3m
    labels:
      severity: warning
    annotations:
      summary: "High error rate for upstream {{ $labels.service }}"

  # Auth failures spike
  - alert: AuthFailureSpike
    expr: |
      rate(auth_failures_total[5m]) > 100
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "Spike in authentication failures"
      description: "Potential security issue or misconfiguration"
```

### 5.2 Notification Channels

**Configure in Alertmanager:**

```yaml
# alertmanager.yaml

route:
  receiver: default
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 5m
  repeat_interval: 12h

  routes:
  # Critical alerts - page immediately
  - match:
      severity: critical
    receiver: pagerduty
    continue: true

  # Warning alerts - Slack only
  - match:
      severity: warning
    receiver: slack

receivers:
- name: default
  slack_configs:
  - api_url: '${SLACK_WEBHOOK_URL}'
    channel: '#ops-alerts'

- name: pagerduty
  pagerduty_configs:
  - service_key: '${PAGERDUTY_SERVICE_KEY}'

- name: slack
  slack_configs:
  - api_url: '${SLACK_WEBHOOK_URL}'
    channel: '#api-gateway-alerts'
```

---

## 6. Operational Runbooks

Quick reference runbooks are maintained in [RUNBOOK.md](./RUNBOOK.md).

### 6.1 Common Operations

- [Scaling the Gateway](./RUNBOOK.md#scaling-the-gateway)
- [Rolling Back a Deployment](./RUNBOOK.md#rolling-back)
- [Updating Configuration](./RUNBOOK.md#configuration-changes)
- [Certificate Rotation](./RUNBOOK.md#certificate-rotation)

### 6.2 Troubleshooting

- [High Error Rates](./RUNBOOK.md#high-error-rates)
- [High Latency](./RUNBOOK.md#high-latency)
- [Authentication Issues](./RUNBOOK.md#authentication-issues)
- [Rate Limiting Problems](./RUNBOOK.md#rate-limiting-problems)

---

## Appendix A: Configuration Examples

### Example: Production Configuration with Full Observability

```yaml
# config.production.yaml

server:
  bind_address: "0.0.0.0"
  port: 8443
  connection_timeout_secs: 60
  max_connections: 10000
  request_timeout_secs: 30
  tls:
    cert_path: /etc/tls/cert.pem
    key_path: /etc/tls/key.pem
    min_version: "1.2"

logging:
  level: INFO
  format: json
  structured: true
  redaction_enabled: true
  sampling_rate: 1.0
  sinks:
    - type: stdout
      enabled: true
      min_level: INFO

    - type: elasticsearch
      enabled: true
      elasticsearch:
        urls:
          - "https://elasticsearch.prod.example.com:9200"
        index: "api-gateway-logs-%Y.%m.%d"
        batch_size: 100
        flush_interval_secs: 5
        username: gateway
        password: "${ELASTICSEARCH_PASSWORD}"

observability:
  metrics_enabled: true
  metrics_port: 9090
  health_checks:
    liveness_enabled: true
    readiness_enabled: true
    check_redis: true
    check_upstreams: false
  tracing:
    enabled: true
    backend: jaeger
    endpoint: "http://jaeger-collector:14268/api/traces"
    service_name: "api-gateway"
    sampling_rate: 0.1

auth:
  token_format: jwt
  jwt_algorithm: HS256
  jwt_secret: "${JWT_SECRET}"
  jwt_issuer: "auth.example.com"
  jwt_audience: "api.example.com"
  cookie_name: "session_token"
  cache:
    enabled: true
    max_capacity: 100000
    ttl_secs: 300

rate_limiting:
  redis_url: "redis://redis-master.production.svc.cluster.local:6379"
  failure_mode: fail_closed
  default_limit:
    limit: 1000
    window_secs: 3600
    algorithm: token_bucket
    key_type: ip

upstreams:
  - id: user-service
    base_url: http://user-service.production.svc.cluster.local:8080
    timeout_secs: 30
    pool_max_idle_per_host: 50

routes:
  - id: users-list
    methods: [GET]
    path: /api/users
    upstream_id: user-service
    auth_required: true
    rate_limit:
      limit: 100
      window_secs: 60
      algorithm: sliding_window
      key_type: user
```

---

## Appendix B: Checklist - Pre-Production Readiness

- [ ] **Logging**
  - [ ] Centralized logging configured (Elasticsearch/CloudWatch/Splunk)
  - [ ] Log retention policies set
  - [ ] Sensitive data redaction enabled
  - [ ] Log aggregation tested

- [ ] **Monitoring**
  - [ ] Prometheus metrics collection configured
  - [ ] Grafana dashboards created
  - [ ] Critical alerts configured
  - [ ] Alert routing to PagerDuty/Opsgenie set up

- [ ] **Capacity**
  - [ ] Load testing completed
  - [ ] Horizontal Pod Autoscaler configured
  - [ ] Resource requests and limits set
  - [ ] Capacity projections documented

- [ ] **Backup & Recovery**
  - [ ] Configuration in version control
  - [ ] Automated configuration backups scheduled
  - [ ] Redis persistence enabled
  - [ ] Disaster recovery plan tested

- [ ] **Security**
  - [ ] TLS certificates installed and validated
  - [ ] Secrets management in place (not hardcoded)
  - [ ] Security scanning completed
  - [ ] Rate limiting configured

- [ ] **Documentation**
  - [ ] Runbook updated
  - [ ] Incident response plan reviewed
  - [ ] On-call rotation established
  - [ ] Team trained on operational procedures

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-03-15 | Engineering Team | Initial operational readiness documentation |
