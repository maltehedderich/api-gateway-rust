# API Gateway Deployment Guide

This guide provides comprehensive instructions for deploying the API Gateway in various environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Configuration Management](#configuration-management)
- [Monitoring and Observability](#monitoring-and-observability)
- [Security Considerations](#security-considerations)
- [Scaling and High Availability](#scaling-and-high-availability)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### General Requirements

- **Docker**: Version 20.10 or later (for containerized deployment)
- **Kubernetes**: Version 1.20 or later (for Kubernetes deployment)
- **kubectl**: Configured to access your Kubernetes cluster
- **Helm** (optional): Version 3.x for package management

### Runtime Dependencies

- **Redis** (optional): Required if using rate limiting
  - Version 6.0 or later
  - Cluster or standalone deployment
  - Authentication recommended for production

- **Session Store** (optional): Required if using opaque tokens
  - Redis or compatible database
  - High availability recommended

### Build Dependencies

- **Rust**: Version 1.75 or later
- **Cargo**: Included with Rust installation

## Docker Deployment

### Building the Docker Image

The project includes a multi-stage Dockerfile optimized for production use.

```bash
# Build the Docker image
docker build -t api-gateway-rust:latest .

# Build with specific version tag
docker build -t api-gateway-rust:v1.0.0 .

# Build with build arguments
docker build \
  --build-arg RUST_VERSION=1.75 \
  -t api-gateway-rust:latest .
```

### Running the Container

#### Basic Deployment

```bash
docker run -d \
  --name api-gateway \
  -p 8080:8080 \
  -p 9090:9090 \
  api-gateway-rust:latest
```

#### With Custom Configuration

```bash
docker run -d \
  --name api-gateway \
  -p 8080:8080 \
  -p 9090:9090 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  api-gateway-rust:latest
```

#### With Environment Variables

```bash
docker run -d \
  --name api-gateway \
  -p 8080:8080 \
  -p 9090:9090 \
  -e GATEWAY_LOG_LEVEL=debug \
  -e GATEWAY_SERVER__PORT=8080 \
  -e GATEWAY_AUTH__JWT_SECRET=your-secret-key \
  api-gateway-rust:latest
```

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  api-gateway:
    image: api-gateway-rust:latest
    build: .
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      - GATEWAY_LOG_LEVEL=info
      - GATEWAY_SERVER__PORT=8080
      - GATEWAY_AUTH__JWT_SECRET=${JWT_SECRET}
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    depends_on:
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "/app/api-gateway-rust", "--health-check"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 10s

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

Run with Docker Compose:

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f api-gateway

# Stop services
docker-compose down
```

## Kubernetes Deployment

### Quick Start

```bash
# Navigate to k8s directory
cd k8s

# Create namespace (optional)
kubectl create namespace api-gateway

# Create secrets
kubectl create secret generic api-gateway-secrets \
  --from-literal=jwt_secret="your-jwt-secret-here" \
  --from-literal=redis_password="your-redis-password" \
  --namespace=default

# Apply ConfigMap
kubectl apply -f configmap.yaml

# Apply deployment and service
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Verify deployment
kubectl get pods -l app=api-gateway
kubectl get svc api-gateway
```

### Step-by-Step Deployment

#### 1. Prepare Configuration

Edit `k8s/configmap.yaml` to customize your configuration:

```bash
# Edit ConfigMap
kubectl edit configmap api-gateway-config

# Or apply updated file
kubectl apply -f k8s/configmap.yaml
```

#### 2. Create Secrets

**Option A: From literals**

```bash
kubectl create secret generic api-gateway-secrets \
  --from-literal=jwt_secret="$(openssl rand -base64 32)" \
  --from-literal=redis_password="your-redis-password" \
  --namespace=default
```

**Option B: From files**

```bash
# Create secret files
echo -n "your-jwt-secret" > /tmp/jwt_secret
echo -n "your-redis-password" > /tmp/redis_password

# Create secret from files
kubectl create secret generic api-gateway-secrets \
  --from-file=jwt_secret=/tmp/jwt_secret \
  --from-file=redis_password=/tmp/redis_password \
  --namespace=default

# Clean up temporary files
rm /tmp/jwt_secret /tmp/redis_password
```

**Option C: Using template**

```bash
# Copy template
cp k8s/secrets.yaml.template k8s/secrets.yaml

# Edit with your base64-encoded secrets
# Note: Add secrets.yaml to .gitignore!
kubectl apply -f k8s/secrets.yaml
```

#### 3. Deploy Application

```bash
# Apply all manifests
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Wait for rollout to complete
kubectl rollout status deployment/api-gateway

# Check pod status
kubectl get pods -l app=api-gateway
```

#### 4. Verify Deployment

```bash
# Check pod logs
kubectl logs -l app=api-gateway --tail=100

# Check health endpoints
kubectl port-forward svc/api-gateway 8080:80
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready

# Check metrics
kubectl port-forward svc/api-gateway-metrics 9090:9090
curl http://localhost:9090/metrics
```

### Ingress Configuration

Create an Ingress resource to expose the API Gateway:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-gateway-ingress
  namespace: default
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - api.example.com
    secretName: api-gateway-tls
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway
            port:
              number: 80
```

Apply the Ingress:

```bash
kubectl apply -f ingress.yaml
```

### Horizontal Pod Autoscaling

Create an HPA to automatically scale based on CPU/memory:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway-hpa
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  minReplicas: 3
  maxReplicas: 10
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
        periodSeconds: 60
```

Apply the HPA:

```bash
kubectl apply -f hpa.yaml
```

## Configuration Management

### Configuration Hierarchy

Configuration is loaded in the following order (later sources override earlier ones):

1. Default values (hardcoded in application)
2. Configuration file (`config.yaml`)
3. Environment variables (prefixed with `GATEWAY_`)
4. Command-line arguments

### Environment Variables

All configuration options can be set via environment variables using the `GATEWAY_` prefix:

```bash
# Server configuration
GATEWAY_SERVER__PORT=8080
GATEWAY_SERVER__BIND_ADDRESS=0.0.0.0

# Logging
GATEWAY_LOG_LEVEL=info

# Authentication
GATEWAY_AUTH__JWT_SECRET=your-secret
GATEWAY_AUTH__JWT_ALGORITHM=HS256
GATEWAY_AUTH__COOKIE_NAME=session_token

# Rate limiting
GATEWAY_RATE_LIMITING__REDIS_URL=redis://redis:6379
GATEWAY_RATE_LIMITING__FAILURE_MODE=fail_closed
```

### ConfigMap Updates

To update configuration without downtime:

```bash
# Edit ConfigMap
kubectl edit configmap api-gateway-config

# Or apply updated file
kubectl apply -f k8s/configmap.yaml

# Restart pods to pick up new configuration
kubectl rollout restart deployment/api-gateway

# Or use a sidecar to automatically reload on ConfigMap change
```

### Secrets Rotation

To rotate secrets:

```bash
# Update secret
kubectl create secret generic api-gateway-secrets \
  --from-literal=jwt_secret="new-secret" \
  --namespace=default \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart pods
kubectl rollout restart deployment/api-gateway
```

## Monitoring and Observability

### Prometheus Setup

#### Install Prometheus Operator (if not already installed)

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace
```

#### Deploy ServiceMonitor

```bash
kubectl apply -f k8s/servicemonitor.yaml
```

#### Deploy PrometheusRule

```bash
kubectl apply -f k8s/monitoring/prometheus-rules.yaml
```

#### Verify Metrics Collection

```bash
# Port-forward to Prometheus
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090

# Open http://localhost:9090 in browser
# Query: up{job="api-gateway"}
```

### Grafana Setup

#### Access Grafana

```bash
# Get Grafana admin password
kubectl get secret -n monitoring prometheus-grafana \
  -o jsonpath="{.data.admin-password}" | base64 -d

# Port-forward to Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80

# Open http://localhost:3000 in browser
# Username: admin
# Password: (from above command)
```

#### Import Dashboard

1. Open Grafana UI
2. Navigate to Dashboards → Import
3. Upload `k8s/monitoring/grafana-dashboard.json`
4. Select Prometheus datasource
5. Click Import

Or via API:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d @k8s/monitoring/grafana-dashboard.json \
  http://admin:password@localhost:3000/api/dashboards/db
```

### Logging

#### View Logs

```bash
# Tail logs from all pods
kubectl logs -f -l app=api-gateway

# Tail logs from specific pod
kubectl logs -f api-gateway-<pod-id>

# View logs from previous container (after crash)
kubectl logs -p api-gateway-<pod-id>

# View logs with timestamps
kubectl logs -f -l app=api-gateway --timestamps
```

#### Log Aggregation

For production, integrate with a log aggregation service:

**Elasticsearch + Fluentd/Fluent Bit**

```bash
# Install ECK (Elastic Cloud on Kubernetes)
kubectl create -f https://download.elastic.co/downloads/eck/2.10.0/crds.yaml
kubectl apply -f https://download.elastic.co/downloads/eck/2.10.0/operator.yaml

# Deploy Elasticsearch and Kibana
# (Configuration depends on your setup)
```

**Loki + Promtail**

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm install loki grafana/loki-stack \
  --namespace monitoring \
  --set promtail.enabled=true \
  --set grafana.enabled=true
```

## Security Considerations

### TLS/HTTPS

#### Using cert-manager

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

### Network Policies

Restrict network access to the API Gateway:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-gateway-netpol
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: api-gateway
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 8080  # Upstream services
  - to:
    - namespaceSelector:
        matchLabels:
          name: default
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

### Pod Security

The deployment uses security best practices:

- Non-root user (UID 1000)
- Read-only root filesystem
- No privilege escalation
- Dropped all capabilities
- Seccomp profile

## Scaling and High Availability

### Replica Configuration

For production, run at least 3 replicas:

```bash
kubectl scale deployment/api-gateway --replicas=3
```

### Resource Limits

Adjust based on your workload:

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### Pod Disruption Budget

Ensure high availability during voluntary disruptions:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: api-gateway-pdb
  namespace: default
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: api-gateway
```

Apply PDB:

```bash
kubectl apply -f pdb.yaml
```

## Troubleshooting

### Common Issues

#### Pods Not Starting

```bash
# Check pod status
kubectl get pods -l app=api-gateway

# Describe pod for events
kubectl describe pod api-gateway-<pod-id>

# Check logs
kubectl logs api-gateway-<pod-id>

# Check previous container logs (if crashed)
kubectl logs -p api-gateway-<pod-id>
```

#### Configuration Issues

```bash
# Verify ConfigMap
kubectl get configmap api-gateway-config -o yaml

# Verify Secrets exist
kubectl get secret api-gateway-secrets

# Check environment variables in pod
kubectl exec api-gateway-<pod-id> -- env | grep GATEWAY
```

#### Health Check Failures

```bash
# Check liveness probe
kubectl describe pod api-gateway-<pod-id> | grep Liveness

# Check readiness probe
kubectl describe pod api-gateway-<pod-id> | grep Readiness

# Manually test health endpoints
kubectl exec api-gateway-<pod-id> -- curl http://localhost:8080/health/live
kubectl exec api-gateway-<pod-id> -- curl http://localhost:8080/health/ready
```

#### Performance Issues

```bash
# Check resource usage
kubectl top pods -l app=api-gateway

# Check metrics
kubectl port-forward svc/api-gateway-metrics 9090:9090
curl http://localhost:9090/metrics | grep http_requests

# Check HPA status
kubectl get hpa api-gateway-hpa
kubectl describe hpa api-gateway-hpa
```

### Getting Support

For issues not covered here, see:

- [RUNBOOK.md](RUNBOOK.md) - Operational runbook
- [TESTING.md](TESTING.md) - Testing guide
- [GitHub Issues](https://github.com/your-org/api-gateway-rust/issues)

## Next Steps

- Review [RUNBOOK.md](RUNBOOK.md) for operational procedures
- Set up monitoring alerts
- Configure log aggregation
- Implement backup and disaster recovery procedures
- Perform load testing
- Set up CI/CD pipeline for automated deployments
