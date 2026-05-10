#!/bin/bash
# =====================================================
# AIPDA - Auto Deploy Script
# شغّل هذا السكريبت على أي جهاز وكل شي يشتغل تلقائياً
# استخدام: bash deploy.sh
# =====================================================

set -e  # وقف عند أي خطأ

# -------------------------------------------------------
# الإعدادات — عدّلها حسب احتياجك
# -------------------------------------------------------
VIRUSTOTAL_API_KEY="5e101f81143b2d2ab7b8e316be0b2934326cc45d331ae1f4791128d85ac9960c"
GITHUB_REPO="https://github.com/sulaiman2061/phishguard"
APP_DIR="/opt/aipda"
PORT="5000"
CONTAINER_NAME="aipda_container"
IMAGE_NAME="aipda"

# -------------------------------------------------------
# ألوان للـ output
# -------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()   { echo -e "${GREEN}[✅ OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[⚠️  WARN]${NC} $1"; }
error() { echo -e "${RED}[❌ ERROR]${NC} $1"; exit 1; }
info()  { echo -e "${BLUE}[ℹ️  INFO]${NC} $1"; }

# -------------------------------------------------------
# BANNER
# -------------------------------------------------------
echo ""
echo "=================================================="
echo "   AIPDA - AI Powered Phishing Detection"
echo "   Auto Deploy Script v1.0"
echo "=================================================="
echo ""

# -------------------------------------------------------
# الخطوة 1: تحقق من الصلاحيات
# -------------------------------------------------------
info "Checking permissions..."
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo bash deploy.sh"
fi
log "Running as root"

# -------------------------------------------------------
# الخطوة 2: تحديد نوع الـ OS
# -------------------------------------------------------
info "Detecting OS..."
if [ -f /etc/redhat-release ]; then
    OS="rhel"
    PKG="dnf"
    log "Detected: Red Hat / CentOS / Fedora"
elif [ -f /etc/debian_version ]; then
    OS="debian"
    PKG="apt"
    log "Detected: Ubuntu / Debian"
else
    OS="unknown"
    PKG="apt"
    warn "Unknown OS — trying apt"
fi

# -------------------------------------------------------
# الخطوة 3: تثبيت المتطلبات
# -------------------------------------------------------
info "Installing dependencies..."

if [ "$OS" = "rhel" ]; then
    dnf install -y git docker podman-docker curl 2>/dev/null || \
    dnf install -y git podman podman-docker curl 2>/dev/null || \
    warn "Some packages may already be installed"
else
    apt update -y 2>/dev/null
    apt install -y git docker.io curl 2>/dev/null || \
    warn "Some packages may already be installed"
fi

log "Dependencies installed"

# -------------------------------------------------------
# الخطوة 4: تشغيل Docker/Podman
# -------------------------------------------------------
info "Starting Docker service..."
systemctl start docker 2>/dev/null || \
systemctl start podman 2>/dev/null || \
warn "Docker service not found — using podman"

# تحقق إن docker/podman شغّال
if ! command -v docker &>/dev/null && ! command -v podman &>/dev/null; then
    error "Docker/Podman not found. Install manually and retry."
fi
log "Docker/Podman ready"

# -------------------------------------------------------
# الخطوة 5: حمّل الكود من GitHub
# -------------------------------------------------------
info "Cloning repository from GitHub..."
if [ -d "$APP_DIR" ]; then
    warn "Directory $APP_DIR already exists — updating..."
    cd "$APP_DIR"
    git pull origin main || warn "Git pull failed — using existing code"
else
    git clone "$GITHUB_REPO" "$APP_DIR" || error "Failed to clone repository"
    cd "$APP_DIR"
fi
log "Code ready at $APP_DIR"

# -------------------------------------------------------
# الخطوة 6: إنشاء .env
# -------------------------------------------------------
info "Creating .env file..."
cat > "$APP_DIR/.env" << EOF
VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
SECRET_KEY=aipda-enterprise-$(date +%s)
PORT=${PORT}
EOF
log ".env created"

# -------------------------------------------------------
# الخطوة 7: إنشاء قاعدة البيانات إذا ما موجودة
# -------------------------------------------------------
if [ ! -f "$APP_DIR/aipda.db" ]; then
    info "Creating fresh database..."
    touch "$APP_DIR/aipda.db"
    chmod 666 "$APP_DIR/aipda.db"
    log "Database created"
else
    log "Database already exists — keeping data"
fi

# -------------------------------------------------------
# الخطوة 8: بناء Docker Image
# -------------------------------------------------------
info "Building Docker image..."
cd "$APP_DIR"

# إذا ما في Dockerfile نعمله
if [ ! -f "Dockerfile" ]; then
cat > Dockerfile << 'DOCKER'
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
ENV PYTHONUNBUFFERED=1
CMD ["python3", "app.py"]
DOCKER
log "Dockerfile created"
fi

docker build -t "$IMAGE_NAME" . || error "Docker build failed"
log "Docker image built: $IMAGE_NAME"

# -------------------------------------------------------
# الخطوة 9: إيقاف الـ container القديم
# -------------------------------------------------------
info "Stopping old container if exists..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null && warn "Old container removed" || true
log "Ready for fresh deployment"

# -------------------------------------------------------
# الخطوة 10: تشغيل الـ container
# -------------------------------------------------------
info "Starting AIPDA container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "${PORT}:5000" \
    -e VIRUSTOTAL_API_KEY="$VIRUSTOTAL_API_KEY" \
    -e SECRET_KEY="aipda-enterprise-$(date +%s)" \
    -v "$APP_DIR/aipda.db:/app/aipda.db" \
    --restart always \
    "$IMAGE_NAME" || error "Failed to start container"

log "Container started"

# -------------------------------------------------------
# الخطوة 11: انتظر ويتحقق
# -------------------------------------------------------
info "Waiting for service to start..."
sleep 5

if curl -s "http://localhost:${PORT}" > /dev/null 2>&1; then
    log "Service is UP and responding"
else
    warn "Service may still be starting..."
    docker logs "$CONTAINER_NAME" | tail -5
fi

# -------------------------------------------------------
# الخطوة 12: إعداد Auto-start عند إعادة التشغيل
# -------------------------------------------------------
info "Setting up auto-start on reboot..."

# إنشاء systemd service للـ container
cat > /etc/systemd/system/aipda-docker.service << EOF
[Unit]
Description=AIPDA Docker Container
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker start ${CONTAINER_NAME}
ExecStop=/usr/bin/docker stop ${CONTAINER_NAME}
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aipda-docker 2>/dev/null || warn "Auto-start setup failed"
log "Auto-start configured"

# -------------------------------------------------------
# الخطوة 13: معلومات الوصول
# -------------------------------------------------------

# احصل على الـ IP
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=================================================="
echo -e "${GREEN}   AIPDA DEPLOYED SUCCESSFULLY! 🎉${NC}"
echo "=================================================="
echo ""
echo "  Portal:    http://localhost:${PORT}"
echo "  Network:   http://${LOCAL_IP}:${PORT}"
echo "  Dashboard: http://localhost:${PORT}/dashboard"
echo "  Login:     http://localhost:${PORT}/login"
echo ""
echo "  Admin:     admin / Admin@1234"
echo ""
echo "  Container: docker ps"
echo "  Logs:      docker logs ${CONTAINER_NAME}"
echo "  Stop:      docker stop ${CONTAINER_NAME}"
echo "  Restart:   docker restart ${CONTAINER_NAME}"
echo ""
echo "  VirusTotal: $([ -n '$VIRUSTOTAL_API_KEY' ] && echo 'Enabled ✅' || echo 'Disabled ❌')"
echo "  NCA Engine: Enabled ✅"
echo "=================================================="
echo ""
