#!/bin/bash
# Helper script to manage Vault container for integration testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ADDR="http://localhost:8200"
VAULT_TOKEN="myroot"
CONTAINER_NAME="vault-test"
VOLUME_NAME="vault-data"

start_vault() {
    echo "Starting Vault container..."

    # Clean up any existing container
    podman stop "$CONTAINER_NAME" 2>/dev/null || true
    podman rm "$CONTAINER_NAME" 2>/dev/null || true

    # Create volume if it doesn't exist
    podman volume create "$VOLUME_NAME" 2>/dev/null || true

    # Start the vault container
    podman run -d \
        --name "$CONTAINER_NAME" \
        --rm \
        -p "8200:8200" \
        -e "VAULT_DEV_ROOT_TOKEN_ID=myroot" \
        -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
        -e "VAULT_ADDR=http://0.0.0.0:8200" \
        --cap-add IPC_LOCK \
        -v "$VOLUME_NAME:/vault/data" \
        -v "$SCRIPT_DIR/vault-config:/vault/config" \
        "docker.io/hashicorp/vault:1.15.2" \
        vault server -dev -dev-root-token-id=myroot -dev-listen-address=0.0.0.0:8200

    echo "Waiting for Vault to be ready..."
    sleep 5
    timeout=30
    elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
            echo "Vault started at $VAULT_ADDR with token: $VAULT_TOKEN"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo "❌ Vault failed to start within $timeout seconds"
    return 1
}

stop_vault() {
    echo "Stopping Vault container..."
    podman stop "$CONTAINER_NAME" 2>/dev/null || true
    podman volume rm "$VOLUME_NAME" 2>/dev/null || true
    echo "Vault stopped and volumes cleaned"
}

case "${1:-help}" in
    start)
        start_vault
        ;;

    stop)
        stop_vault
        ;;

    restart)
        echo "Restarting Vault container..."
        stop_vault
        start_vault
        ;;

    status)
        echo "Checking Vault status..."
        if curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null; then
            echo "✅ Vault is running and healthy at $VAULT_ADDR"
            echo "🔑 Token: $VAULT_TOKEN"
        else
            echo "❌ Vault is not responding at $VAULT_ADDR"
            exit 1
        fi
        ;;

    logs)
        echo "Showing Vault logs..."
        podman logs "$CONTAINER_NAME"
        ;;

    exec)
        echo "Executing command in Vault container..."
        shift
        podman exec -it "$CONTAINER_NAME" "$@"
        ;;

    vault-cli)
        echo "Running vault CLI command..."
        shift
        podman exec "$CONTAINER_NAME" sh -c "VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=$VAULT_TOKEN vault $*"
        ;;

    test)
        echo "Running a quick test..."
        if start_vault; then
            echo "✅ Test passed - Vault is healthy"
            stop_vault
            echo "✅ Test completed successfully"
        else
            echo "❌ Test failed - Vault is not responding"
            stop_vault
            exit 1
        fi
        ;;

    help|*)
        echo "Vault Integration Test Helper"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  start     Start Vault container"
        echo "  stop      Stop Vault container and clean volumes"
        echo "  restart   Restart Vault container"
        echo "  status    Check if Vault is running"
        echo "  logs      Show Vault container logs"
        echo "  exec      Execute command in Vault container"
        echo "  vault-cli Run vault CLI command"
        echo "  test      Run a quick integration test"
        echo "  help      Show this help message"
        echo ""
        echo "Environment:"
        echo "  VAULT_ADDR: $VAULT_ADDR"
        echo "  VAULT_TOKEN: $VAULT_TOKEN"
        echo "  CONTAINER_NAME: $CONTAINER_NAME"
        echo "  VOLUME_NAME: $VOLUME_NAME"
        ;;
esac