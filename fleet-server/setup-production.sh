#!/bin/bash
# ─────────────────────────────────────────────
# Firmware Dashboard — Pi4 Production Setup
# Sets up Nginx + Gunicorn + Flask
# ─────────────────────────────────────────────

set -e

APP_DIR="/home/tom/tools/fleet-server"
NGINX_CONF="/etc/nginx/sites-available/fleet-console"
SYSTEMD_UNIT="/etc/systemd/system/fleet-console.service"

echo ""
echo "═══════════════════════════════════════════"
echo "  Firmware Dashboard — Production Setup"
echo "═══════════════════════════════════════════"
echo ""

# 1. Install Nginx and Gunicorn
echo "[1/6] Installing Nginx and Gunicorn..."
sudo apt-get update -qq
sudo apt-get install -y -qq nginx
pip3 install gunicorn flask --break-system-packages 2>/dev/null || pip3 install gunicorn flask

# 2. Set up first-time user accounts if needed
if [ ! -f "$APP_DIR/users.json" ]; then
    echo ""
    echo "[2/6] Setting up user accounts..."
    cd "$APP_DIR"
    python3 server.py --setup
else
    echo "[2/6] User accounts already exist (run 'python3 server.py --setup' to reset)"
fi

# 3. Install Nginx config
echo "[3/6] Configuring Nginx..."
sudo cp "$APP_DIR/nginx-fleet-console.conf" "$NGINX_CONF"
sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/fleet-console

# Remove default site if it exists (so port 80 goes to our app)
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
    echo "  Removed default Nginx site"
fi

# Test Nginx config
sudo nginx -t

# 4. Install systemd service
echo "[4/6] Installing systemd service..."
sudo cp "$APP_DIR/fleet-console.service" "$SYSTEMD_UNIT"
sudo systemctl daemon-reload

# 5. Start services
echo "[5/6] Starting services..."
sudo systemctl enable fleet-console
sudo systemctl restart fleet-console
sudo systemctl restart nginx

# 6. Verify
echo "[6/6] Verifying..."
sleep 2

if systemctl is-active --quiet fleet-console; then
    echo "  ✓ Gunicorn is running"
else
    echo "  ✗ Gunicorn failed to start — check: sudo journalctl -u fleet-console"
fi

if systemctl is-active --quiet nginx; then
    echo "  ✓ Nginx is running"
else
    echo "  ✗ Nginx failed to start — check: sudo journalctl -u nginx"
fi

# Get IP
IP=$(hostname -I | awk '{print $1}')
HOSTNAME=$(hostname)

echo ""
echo "═══════════════════════════════════════════"
echo "  Setup Complete!"
echo ""
echo "  Dashboard:  http://$IP"
echo "              http://$HOSTNAME"
echo ""
echo "  Services:"
echo "    sudo systemctl status fleet-console"
echo "    sudo systemctl status nginx"
echo ""
echo "  Logs:"
echo "    sudo journalctl -u fleet-console -f"
echo "    sudo tail -f /var/log/nginx/error.log"
echo ""
echo "  To update user accounts:"
echo "    cd $APP_DIR && python3 server.py --setup"
echo "    sudo systemctl restart fleet-console"
echo "═══════════════════════════════════════════"
echo ""
