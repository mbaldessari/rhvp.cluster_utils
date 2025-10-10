#!/bin/bash -eu
# Helper script to manage kind cluster for integration testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="vault-secrets-test"
KUBECONFIG_FILE="$SCRIPT_DIR/kubeconfig-kind"

start_kind() {
    echo "Starting kind cluster..."

    # Check if cluster already exists
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        echo "Cluster $CLUSTER_NAME already exists"
        kind export kubeconfig --name "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG_FILE"
        return 0
    fi

    # Create cluster
    kind create cluster --name "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG_FILE"

    echo "Waiting for cluster to be ready..."
    kubectl --kubeconfig="$KUBECONFIG_FILE" wait --for=condition=Ready nodes --all --timeout=300s

    # Create test namespaces
    kubectl --kubeconfig="$KUBECONFIG_FILE" create namespace test-namespace || true
    kubectl --kubeconfig="$KUBECONFIG_FILE" create namespace production || true
    kubectl --kubeconfig="$KUBECONFIG_FILE" create namespace test-secrets || true

    echo "✅ Kind cluster started and ready"
    echo "📋 Cluster name: $CLUSTER_NAME"
    echo "📄 Kubeconfig: $KUBECONFIG_FILE"
}

stop_kind() {
    echo "Stopping kind cluster..."
    kind delete cluster --name "$CLUSTER_NAME" || true
    rm -f "$KUBECONFIG_FILE"
    echo "Kind cluster stopped and kubeconfig cleaned"
}

status_kind() {
    echo "Checking kind cluster status..."
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        echo "✅ Cluster $CLUSTER_NAME is running"
        if [ -f "$KUBECONFIG_FILE" ]; then
            echo "📄 Kubeconfig available at: $KUBECONFIG_FILE"
            # Test cluster connectivity
            if kubectl --kubeconfig="$KUBECONFIG_FILE" cluster-info > /dev/null 2>&1; then
                echo "🔗 Cluster is accessible"
                kubectl --kubeconfig="$KUBECONFIG_FILE" get nodes
            else
                echo "❌ Cluster is not accessible"
                exit 1
            fi
        else
            echo "⚠️ Kubeconfig not found"
            exit 1
        fi
    else
        echo "❌ Cluster $CLUSTER_NAME is not running"
        exit 1
    fi
}

test_kind() {
    echo "Running a quick test..."
    if start_kind; then
        echo "✅ Test passed - Kind cluster is healthy"
        kubectl --kubeconfig="$KUBECONFIG_FILE" get namespaces
        stop_kind
        echo "✅ Test completed successfully"
    else
        echo "❌ Test failed - Kind cluster is not responding"
        stop_kind
        exit 1
    fi
}

case "${1:-help}" in
    start)
        start_kind
        ;;

    stop)
        stop_kind
        ;;

    restart)
        echo "Restarting kind cluster..."
        stop_kind
        start_kind
        ;;

    status)
        status_kind
        ;;

    test)
        test_kind
        ;;

    help|*)
        echo "Kind Integration Test Helper"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  start     Start kind cluster"
        echo "  stop      Stop kind cluster and clean up"
        echo "  restart   Restart kind cluster"
        echo "  status    Check if kind cluster is running"
        echo "  test      Run a quick integration test"
        echo "  help      Show this help message"
        echo ""
        echo "Environment:"
        echo "  CLUSTER_NAME: $CLUSTER_NAME"
        echo "  KUBECONFIG: $KUBECONFIG_FILE"
        ;;
esac
