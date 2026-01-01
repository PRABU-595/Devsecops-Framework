# Installation Guide

Complete setup instructions for the Unified DevSecOps Framework for Kubernetes.

---

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Prerequisites](#prerequisites)
3. [Installation Methods](#installation-methods)
4. [Verification](#verification)
5. [Configuration](#configuration)
6. [Troubleshooting](#troubleshooting)

---

## 🖥️ System Requirements

### Minimum Requirements

- **CPU:** 2 cores
- **RAM:** 4GB
- **Disk:** 20GB free space
- **OS:** Ubuntu 20.04+ / macOS 12+ / Windows 10+ with WSL2

### Recommended for Production

- **CPU:** 4+ cores
- **RAM:** 16GB
- **Disk:** 50GB free space
- **Network:** Stable internet connection

### Tested Configurations

| Environment | Specs | Status |
|-------------|-------|--------|
| K3s v1.32.6 (3-node) | 4 vCPU, 16GB RAM | ✅ 101 days uptime |
| Minikube v1.37 | 2 vCPU, 4GB RAM | ✅ Tested |
| GKE (Standard) | n1-standard-2 | ✅ Compatible |
| EKS (AWS) | t3.medium | ✅ Compatible |

---

## 🔧 Prerequisites

### Required Software

#### 1. Docker

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and back in for group changes
```

**macOS:**
```bash
brew install --cask docker
# Or download from https://www.docker.com/products/docker-desktop
```

#### 2. kubectl (Kubernetes CLI)

```bash
# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# macOS
brew install kubectl

# Verify
kubectl version --client
```

#### 3. Helm v3+

```bash
# Linux & macOS
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Verify
helm version
```

#### 4. Minikube (for local testing)

```bash
# Linux
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# macOS
brew install minikube

# Verify
minikube version
```

#### 5. Python 3.8+

```bash
# Ubuntu/Debian
sudo apt-get install -y python3 python3-pip python3-venv

# macOS
brew install python3

# Verify
python3 --version
```

---

## 📦 Installation Methods

### Method 1: Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/kubernetes-devsecops-framework.git
cd kubernetes-devsecops-framework

# Run automated installer
chmod +x scripts/install_dependencies.sh
./scripts/install_dependencies.sh
```

This script installs:
- kubectl
- Helm
- Minikube
- Python packages (scikit-learn, numpy, pandas, pyyaml)

---

### Method 2: Manual Installation

#### Step 1: Install Python Dependencies

```bash
python3 -m pip install --upgrade pip

# Core dependencies
pip3 install numpy pandas scikit-learn pyyaml

# Optional (for visualization)
pip3 install matplotlib seaborn scipy
```

**Ubuntu 24.04 Fix (externally-managed-environment):**
```bash
# Option 1: Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install numpy pandas scikit-learn pyyaml

# Option 2: Use --break-system-packages (if needed)
pip3 install numpy --break-system-packages
```

#### Step 2: Start Kubernetes Cluster

**Using Minikube:**
```bash
minikube start --driver=docker --cpus=2 --memory=4096 --disk-size=20g
minikube status
```

**Using K3s (Production):**
```bash
curl -sfL https://get.k3s.io | sh -
sudo kubectl get nodes
```

**Using Existing Cluster:**
```bash
# Ensure kubectl is configured
kubectl cluster-info
kubectl get nodes
```

#### Step 3: Deploy OPA Gatekeeper

```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.0/deploy/gatekeeper.yaml

# Wait for deployment
kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=5m

# Verify
kubectl get pods -n gatekeeper-system
```

#### Step 4: Deploy Falco (Optional for Runtime Security)

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true

# Verify
kubectl get pods -n falco
```

#### Step 5: Apply Custom Policies

```bash
cd kubernetes-devsecops-framework

# Apply constraint templates
kubectl apply -f policies/constraint_templates/

# Wait for CRDs to be ready
sleep 10

# Apply constraints
kubectl apply -f policies/constraints/

# Verify policies
kubectl get constrainttemplates
kubectl get constraints
```

---

## ✅ Verification

### 1. Verify Cluster

```bash
kubectl cluster-info
kubectl get nodes
```

**Expected output:**
```
Kubernetes control plane is running at https://...
KubeDNS is running at https://...

NAME       STATUS   ROLES                  AGE   VERSION
minikube   Ready    control-plane,master   5m    v1.34.0
```

### 2. Verify OPA Gatekeeper

```bash
kubectl get pods -n gatekeeper-system
```

**Expected output:**
```
NAME                                             READY   STATUS    RESTARTS
gatekeeper-audit-xxx                             1/1     Running   0
gatekeeper-controller-manager-xxx                1/1     Running   0
gatekeeper-controller-manager-yyy                1/1     Running   0
```

### 3. Verify Policies

```bash
kubectl get constrainttemplates
kubectl get k8sblockprivileged
```

**Expected output:**
```
NAME                      CREATED AT
k8sblockprivileged        2025-01-01T...
k8sblockhostnamespace     2025-01-01T...
...
```

### 4. Test Policy Enforcement

```bash
# This should be BLOCKED
kubectl apply -f test_scenarios/malicious/privilege_escalation/privileged_pod.yaml
```

**Expected output:**
```
Error from server (Forbidden): error when creating "...": admission webhook "..." denied the request: [block-privilege-escalation] Privileged container is not allowed: attacker
```

### 5. Test Legitimate Workload

```bash
# This should be ALLOWED
kubectl apply -f test_scenarios/benign/nginx_secure.yaml
```

**Expected output:**
```
pod/nginx-secure created
```

---

## ⚙️ Configuration

### Customize Policy Strictness

Edit `policies/constraints/security_constraints.yaml`:

```yaml
# Less strict (allow some privilege escalation for specific namespaces)
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system", "monitoring"]
```

### Adjust Resource Requirements

Edit constraint templates to modify resource limits:

```yaml
# policies/constraint_templates/require_resources.yaml
parameters:
  cpu_min: "10m"      # Minimum CPU
  memory_min: "16Mi"  # Minimum memory
  cpu_max: "2000m"    # Maximum CPU
  memory_max: "2Gi"   # Maximum memory
```

### Enable/Disable Specific Policies

```bash
# Disable a specific constraint
kubectl delete k8sblockprivileged block-privilege-escalation

# Re-enable
kubectl apply -f policies/constraints/security_constraints.yaml
```

---

## 🚀 Running the Framework

### Quick Test (100 scenarios)

```bash
cd scripts
chmod +x enhanced_framework_v2.sh
./enhanced_framework_v2.sh
```

**Expected runtime:** ~6 minutes  
**Expected results:**
- Method 1: 100% accuracy (100 scenarios, ~4 sec)
- Method 2: 71-100% blocked (real K8s, ~2 min)
- Method 3: +19% improvement (p < 0.001)

### View Results

```bash
ls -lh results/
cat results/method1_simulation_results.json | jq '.detection_metrics'
```

---

## 🔧 Troubleshooting

### Common Issues

#### Issue 1: "externally-managed-environment" Error

**Solution:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Issue 2: Minikube Won't Start

**Solution:**
```bash
minikube delete
minikube start --driver=docker --cpus=2 --memory=4096
```

#### Issue 3: OPA Not Blocking Pods

**Solution:**
```bash
# Wait for policies to sync (30 seconds)
sleep 30

# Check constraint status
kubectl get constraints

# View audit logs
kubectl logs -n gatekeeper-system -l control-plane=audit-controller
```

#### Issue 4: "No Resources Found"

**Solution:**
```bash
# Verify CRDs are installed
kubectl get crd | grep gatekeeper

# If missing, reinstall Gatekeeper
kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.0/deploy/gatekeeper.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.0/deploy/gatekeeper.yaml
```

For more issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

---

## 🎓 Next Steps

1. ✅ **Run Experiments:** See [EXPERIMENTS.md](EXPERIMENTS.md)
2. ✅ **Understand Methodology:** See [METHODOLOGY.md](METHODOLOGY.md)
3. ✅ **Deploy to Production:** Use K3s/GKE/EKS instead of Minikube
4. ✅ **Customize Policies:** Edit constraint templates for your needs

---

## 📞 Support

- **Issues:** https://github.com/yourusername/kubernetes-devsecops-framework/issues
- **Email:** your-email@example.com
- **Paper:** See CITATION.bib

---

**Installation complete! 🎉**

Run `./scripts/enhanced_framework_v2.sh` to validate your setup.
