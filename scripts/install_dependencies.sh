#!/bin/bash
################################################################################
# Dependency Installation Script for Kubernetes DevSecOps Framework
# Installs all required tools: kubectl, helm, minikube, python dependencies
################################################################################

set -e

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║   Kubernetes DevSecOps Framework - Dependency Installer                   ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

echo "🔍 Detected OS: $OS"
echo ""

# Check if running as root (not recommended)
if [ "$EUID" -eq 0 ]; then 
    echo "⚠️  Warning: Running as root. This is not recommended."
    echo "   Consider running as a regular user with sudo access."
    echo ""
fi

# Install kubectl
echo "📦 Installing kubectl..."
if ! command -v kubectl &> /dev/null; then
    if [ "$OS" == "linux" ]; then
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        chmod +x kubectl
        sudo mv kubectl /usr/local/bin/
    elif [ "$OS" == "mac" ]; then
        brew install kubectl
    fi
    echo "   ✅ kubectl installed"
else
    echo "   ✅ kubectl already installed ($(kubectl version --client --short 2>/dev/null || echo 'version unknown'))"
fi
echo ""

# Install Helm
echo "📦 Installing Helm v3..."
if ! command -v helm &> /dev/null; then
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    echo "   ✅ Helm installed"
else
    echo "   ✅ Helm already installed ($(helm version --short 2>/dev/null || echo 'version unknown'))"
fi
echo ""

# Install Minikube (optional - for local testing)
echo "📦 Installing Minikube (optional)..."
if ! command -v minikube &> /dev/null; then
    if [ "$OS" == "linux" ]; then
        curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
        sudo install minikube-linux-amd64 /usr/local/bin/minikube
        rm minikube-linux-amd64
    elif [ "$OS" == "mac" ]; then
        brew install minikube
    fi
    echo "   ✅ Minikube installed"
else
    echo "   ✅ Minikube already installed ($(minikube version --short 2>/dev/null || echo 'version unknown'))"
fi
echo ""

# Install Docker (if not present)
echo "📦 Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo "   ❌ Docker not found. Please install Docker manually:"
    echo "      Ubuntu: sudo apt-get install docker.io"
    echo "      Mac: brew install --cask docker"
else
    echo "   ✅ Docker installed ($(docker --version))"
fi
echo ""

# Install Python 3 and pip
echo "📦 Installing Python 3 and dependencies..."
if ! command -v python3 &> /dev/null; then
    if [ "$OS" == "linux" ]; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv
    elif [ "$OS" == "mac" ]; then
        brew install python3
    fi
    echo "   ✅ Python 3 installed"
else
    echo "   ✅ Python 3 already installed ($(python3 --version))"
fi
echo ""

# Install Python packages
echo "📦 Installing Python ML libraries..."
python3 -m pip install --upgrade pip --user 2>/dev/null || true

# Try to install packages with fallback options
packages=("numpy" "pandas" "scikit-learn" "pyyaml" "matplotlib" "seaborn" "scipy")

for pkg in "${packages[@]}"; do
    echo -n "   Installing $pkg... "
    if python3 -m pip install "$pkg" --user --quiet 2>/dev/null; then
        echo "✅"
    elif python3 -m pip install "$pkg" --break-system-packages --quiet 2>/dev/null; then
        echo "✅ (system-wide)"
    else
        echo "⚠️  Failed (non-critical)"
    fi
done
echo ""

# Verify installations
echo "🔍 Verifying installations..."
echo "   kubectl: $(kubectl version --client --short 2>/dev/null || echo '❌ Not found')"
echo "   helm: $(helm version --short 2>/dev/null || echo '❌ Not found')"
echo "   minikube: $(min ikube version --short 2>/dev/null || echo '⚠️  Not found (optional)')"
echo "   docker: $(docker --version 2>/dev/null || echo '❌ Not found')"
echo "   python3: $(python3 --version 2>/dev/null || echo '❌ Not found')"
echo "   scikit-learn: $(python3 -c 'import sklearn; print(sklearn.__version__)' 2>/dev/null || echo '⚠️  Not found')"
echo ""

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║   ✅ Installation Complete!                                                ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Next Steps:"
echo "   1. Start a Kubernetes cluster:"
echo "      minikube start --driver=docker --cpus=2 --memory=4096"
echo "   2. Run the framework:"
echo "      cd scripts && ./enhanced_framework_v2.sh"
echo ""
