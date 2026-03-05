#!/bin/bash
set -euo pipefail

APP_DIR="/opt/sez-api"
SERVICE_USER="sezapi"
SERVICE_NAME="sez-api"
PYTHON="python3.11"

if ! command -v "$PYTHON" &>/dev/null; then
    PYTHON="python3"
    echo "WARNING: python3.11 not found, falling back to $($PYTHON --version)"
fi

echo "=== SEZ API installer ==="

# Create service user if needed
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating user $SERVICE_USER..."
    useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
fi

# Stop existing service
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo "Stopping existing service..."
    systemctl stop "$SERVICE_NAME"
fi

# Create app directory
echo "Setting up $APP_DIR..."
mkdir -p "$APP_DIR"

# Copy application files
cp -r sez_api/ "$APP_DIR/"
cp requirements.txt "$APP_DIR/"
cp -n .env "$APP_DIR/.env" 2>/dev/null || true

# Copy certificates if present
for cert in *.pfx *.p12; do
    [ -f "$cert" ] && cp "$cert" "$APP_DIR/"
done

# Recreate venv with target Python if version changed
CURRENT_PY=""
if [ -f "$APP_DIR/.venv/bin/python" ]; then
    CURRENT_PY=$("$APP_DIR/.venv/bin/python" --version 2>/dev/null || echo "")
fi
TARGET_PY=$($PYTHON --version 2>/dev/null)

if [ "$CURRENT_PY" != "$TARGET_PY" ]; then
    echo "Python version change: ${CURRENT_PY:-none} -> $TARGET_PY"
    echo "Recreating virtual environment with $PYTHON..."
    rm -rf "$APP_DIR/.venv"
    $PYTHON -m venv "$APP_DIR/.venv"
elif [ ! -d "$APP_DIR/.venv" ]; then
    echo "Creating virtual environment with $PYTHON..."
    $PYTHON -m venv "$APP_DIR/.venv"
fi

echo "Installing dependencies..."
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

# Set ownership
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
chmod 600 "$APP_DIR/.env"
chmod 600 "$APP_DIR"/*.pfx 2>/dev/null || true
chmod 600 "$APP_DIR"/*.p12 2>/dev/null || true

# Install systemd service
echo "Installing systemd service..."
cp deploy/sez-api.service /etc/systemd/system/"$SERVICE_NAME".service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo "=== SUCCESS ==="
    echo "Service $SERVICE_NAME is running"
    echo "URL: http://$(hostname -I | awk '{print $1}'):8004"
    systemctl status "$SERVICE_NAME" --no-pager -l
else
    echo ""
    echo "=== FAILED ==="
    journalctl -u "$SERVICE_NAME" --no-pager -n 20
    exit 1
fi
