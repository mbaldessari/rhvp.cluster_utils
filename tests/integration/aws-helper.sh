#!/bin/bash -eu

# AWS Secrets Manager LocalStack Helper Script
# This script manages a LocalStack container for testing AWS Secrets Manager integration

CONTAINER_NAME="localstack-test"
LOCALSTACK_PORT="4566"
AWS_ENDPOINT_URL="http://localhost:${LOCALSTACK_PORT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if LocalStack is running
is_localstack_running() {
    if docker ps --format "table {{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        return 0
    else
        return 1
    fi
}

# Function to check if LocalStack is healthy
is_localstack_healthy() {
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if curl -s "${AWS_ENDPOINT_URL}/_localstack/health" | grep -q '"secretsmanager": "available"'; then
            return 0
        fi
        sleep 2
        ((attempt++))
    done
    return 1
}

# Function to start LocalStack
start_localstack() {
    log_info "Starting LocalStack for AWS Secrets Manager testing..."

    if is_localstack_running; then
        log_warn "LocalStack container is already running"
        return 0
    fi

    # Remove any existing stopped container
    docker rm -f ${CONTAINER_NAME} 2>/dev/null || true

    # Start LocalStack container
    docker run -d \
        --name ${CONTAINER_NAME} \
        -p ${LOCALSTACK_PORT}:4566 \
        -e SERVICES=secretsmanager \
        -e DEBUG=1 \
        -e PERSISTENCE=0 \
        docker.io/localstack/localstack:latest

    if [ $? -ne 0 ]; then
        log_error "Failed to start LocalStack container"
        return 1
    fi

    log_info "Waiting for LocalStack Secrets Manager to be ready..."
    if is_localstack_healthy; then
        log_info "LocalStack is ready!"
        return 0
    else
        log_error "LocalStack failed to become healthy within timeout"
        return 1
    fi
}

# Function to stop LocalStack
stop_localstack() {
    log_info "Stopping LocalStack..."

    if is_localstack_running; then
        docker stop ${CONTAINER_NAME}
        docker rm ${CONTAINER_NAME}
        log_info "LocalStack stopped and removed"
    else
        log_warn "LocalStack container is not running"
    fi
}

# Function to get LocalStack status
status_localstack() {
    if is_localstack_running; then
        log_info "LocalStack is running"

        # Check health
        if curl -s "${AWS_ENDPOINT_URL}/_localstack/health" >/dev/null 2>&1; then
            echo "Health check endpoint is accessible"
            curl -s "${AWS_ENDPOINT_URL}/_localstack/health" | python3 -m json.tool
        else
            log_warn "Health check endpoint is not accessible"
        fi
    else
        log_info "LocalStack is not running"
    fi
}

# Function to set environment variables
set_env() {
    cat << EOF
# Set these environment variables to use LocalStack:
export AWS_ENDPOINT_URL=${AWS_ENDPOINT_URL}
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_SIMULATION_MODE=true
EOF
}

# Function to test AWS CLI connectivity
test_connectivity() {
    log_info "Testing AWS CLI connectivity to LocalStack..."

    export AWS_ENDPOINT_URL=${AWS_ENDPOINT_URL}
    export AWS_ACCESS_KEY_ID=test
    export AWS_SECRET_ACCESS_KEY=test
    export AWS_DEFAULT_REGION=us-east-1

    # Test by listing secrets (should return empty list)
    if aws secretsmanager list-secrets --endpoint-url ${AWS_ENDPOINT_URL} >/dev/null 2>&1; then
        log_info "AWS CLI connectivity test passed"
        return 0
    else
        log_error "AWS CLI connectivity test failed"
        return 1
    fi
}

# Function to create test secrets
setup_test_data() {
    log_info "Setting up test data in LocalStack..."

    export AWS_ENDPOINT_URL=${AWS_ENDPOINT_URL}
    export AWS_ACCESS_KEY_ID=test
    export AWS_SECRET_ACCESS_KEY=test
    export AWS_DEFAULT_REGION=us-east-1

    # Create a test secret
    aws secretsmanager create-secret \
        --name "test/demo-secret" \
        --description "Demo secret for integration testing" \
        --secret-string '{"username": "testuser", "password": "testpass123"}' \
        --endpoint-url ${AWS_ENDPOINT_URL} >/dev/null 2>&1

    if [ $? -eq 0 ]; then
        log_info "Test data created successfully"
    else
        log_warn "Failed to create test data (may already exist)"
    fi
}

# Function to clean up test data
cleanup_test_data() {
    log_info "Cleaning up test data..."

    export AWS_ENDPOINT_URL=${AWS_ENDPOINT_URL}
    export AWS_ACCESS_KEY_ID=test
    export AWS_SECRET_ACCESS_KEY=test
    export AWS_DEFAULT_REGION=us-east-1

    # List and delete all secrets
    aws secretsmanager list-secrets --endpoint-url ${AWS_ENDPOINT_URL} --query 'SecretList[].Name' --output text | while read secret_name; do
        if [ -n "$secret_name" ]; then
            aws secretsmanager delete-secret --secret-id "$secret_name" --force-delete-without-recovery --endpoint-url ${AWS_ENDPOINT_URL} >/dev/null 2>&1
        fi
    done

    log_info "Test data cleanup completed"
}

# Main script logic
case "$1" in
    start)
        start_localstack
        ;;
    stop)
        stop_localstack
        ;;
    restart)
        stop_localstack
        sleep 2
        start_localstack
        ;;
    status)
        status_localstack
        ;;
    env)
        set_env
        ;;
    test)
        test_connectivity
        ;;
    setup-data)
        setup_test_data
        ;;
    cleanup-data)
        cleanup_test_data
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|env|test|setup-data|cleanup-data}"
        echo ""
        echo "Commands:"
        echo "  start        - Start LocalStack container"
        echo "  stop         - Stop and remove LocalStack container"
        echo "  restart      - Restart LocalStack container"
        echo "  status       - Show LocalStack status and health"
        echo "  env          - Show environment variables to set"
        echo "  test         - Test AWS CLI connectivity"
        echo "  setup-data   - Create test secrets in LocalStack"
        echo "  cleanup-data - Remove all test secrets from LocalStack"
        exit 1
        ;;
esac
