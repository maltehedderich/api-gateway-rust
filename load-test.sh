#!/bin/bash

# Load Testing Script for API Gateway
# This script uses Apache Bench (ab) to perform load testing
#
# Prerequisites:
#   - Apache Bench (ab) - Install with: apt-get install apache2-utils
#   - or hey - A modern load testing tool: go install github.com/rakyll/hey@latest
#   - or wrk - A modern HTTP benchmarking tool: apt-get install wrk
#
# Usage:
#   ./load-test.sh [target-url] [tool]
#
# Examples:
#   ./load-test.sh http://localhost:8080/health/live ab
#   ./load-test.sh http://localhost:8080/health/live hey
#   ./load-test.sh http://localhost:8080/health/live wrk

set -e

# Configuration
TARGET_URL="${1:-http://localhost:8080/health/live}"
TOOL="${2:-ab}"
CONCURRENT_REQUESTS=100
TOTAL_REQUESTS=10000
DURATION=30  # Duration in seconds for hey and wrk

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}API Gateway Load Testing${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Target URL: ${TARGET_URL}"
echo "Tool: ${TOOL}"
echo "Concurrent Requests: ${CONCURRENT_REQUESTS}"
echo "Total Requests: ${TOTAL_REQUESTS}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run with Apache Bench
run_ab() {
    if ! command_exists ab; then
        echo -e "${RED}Error: Apache Bench (ab) is not installed${NC}"
        echo "Install with: sudo apt-get install apache2-utils"
        exit 1
    fi

    echo -e "${YELLOW}Running Apache Bench load test...${NC}"
    ab -n ${TOTAL_REQUESTS} -c ${CONCURRENT_REQUESTS} -k "${TARGET_URL}"
}

# Function to run with hey
run_hey() {
    if ! command_exists hey; then
        echo -e "${RED}Error: hey is not installed${NC}"
        echo "Install with: go install github.com/rakyll/hey@latest"
        exit 1
    fi

    echo -e "${YELLOW}Running hey load test...${NC}"
    hey -n ${TOTAL_REQUESTS} -c ${CONCURRENT_REQUESTS} -q 0 "${TARGET_URL}"
}

# Function to run with wrk
run_wrk() {
    if ! command_exists wrk; then
        echo -e "${RED}Error: wrk is not installed${NC}"
        echo "Install with: sudo apt-get install wrk"
        exit 1
    fi

    echo -e "${YELLOW}Running wrk load test...${NC}"
    wrk -t10 -c${CONCURRENT_REQUESTS} -d${DURATION}s --latency "${TARGET_URL}"
}

# Function to run with curl (simple sequential test)
run_curl() {
    echo -e "${YELLOW}Running simple curl test (sequential requests)...${NC}"
    echo "Sending 100 sequential requests..."

    success=0
    failed=0
    total_time=0

    for i in {1..100}; do
        start=$(date +%s.%N)
        if curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}" | grep -q "200"; then
            ((success++))
        else
            ((failed++))
        fi
        end=$(date +%s.%N)
        elapsed=$(echo "$end - $start" | bc)
        total_time=$(echo "$total_time + $elapsed" | bc)

        if [ $((i % 20)) -eq 0 ]; then
            echo "Completed $i requests..."
        fi
    done

    avg_time=$(echo "scale=3; $total_time / 100" | bc)

    echo ""
    echo -e "${GREEN}Results:${NC}"
    echo "  Total requests: 100"
    echo "  Successful: ${success}"
    echo "  Failed: ${failed}"
    echo "  Average response time: ${avg_time}s"
}

# Run the selected tool
case ${TOOL} in
    ab)
        run_ab
        ;;
    hey)
        run_hey
        ;;
    wrk)
        run_wrk
        ;;
    curl)
        run_curl
        ;;
    *)
        echo -e "${RED}Error: Unknown tool '${TOOL}'${NC}"
        echo "Supported tools: ab, hey, wrk, curl"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Load test completed!${NC}"
echo ""
echo -e "${YELLOW}Expected Performance Targets (from API_GATEWAY_DESIGN.md):${NC}"
echo "  - Throughput: >10,000 requests/second per instance"
echo "  - Latency: Gateway overhead <10ms"
echo "  - P99 Latency: <500ms"
echo ""
echo "Compare the results above with these targets to verify performance."
