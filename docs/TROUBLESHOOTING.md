# Troubleshooting Guide

Common issues and solutions for the Kubernetes DevSecOps Framework.

---

## 🔧 Installation Issues

### Issue 1: "externally-managed-environment" Error (Ubuntu 24.04)

**Symptons:**
```
error: externally-managed-environment
× This environment is externally managed
```

**Solutions:**

**Option A: Virtual Environment (Recommended)**
```bash
python3 -m venv venv
source venv/bin/activate
pip install numpy pandas scikit-learn pyyaml
```

**Option B: System Packages**
```bash
sudo apt-get install python3-numpy python3-pandas python3-sklearn python3-yaml
```

**Option C: Override (Use Caution)**
```bash
pip3 install numpy --break-system-packages
```

---

### Issue 2: Minikube Won't Start

**Symptoms:**
```
😿  Failed to start minikube: ...
```

**Solutions:**

**1. Check Docker Service:**
```bash
sudo systemctl status docker
sudo systemctl start docker
```

**2. Reset Minikube:**
```bash
minikube delete
minikube start --driver=docker --cpus=2 --memory=4096
```

**3. Check Resources:**
```bash
# Ensure at least 2 CPUs, 4GB RAM available
docker system df
docker system prune -a  # Free up space
```

**4. Try Different Driver:**
```bash
minikube start --driver=kvm2  # or virtualbox, podman
```

---

### Issue 3: kubectl Not Found

**Solution:**
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Verify
kubectl version --client
```

---

## 🛡️ OPA Gatekeeper Issues

### Issue 4: Policies Not Blocking Pods

**Symptoms:**
- Malicious pods are being created
- No admission webhook errors

**Solutions:**

**1. Wait for Policy Sync (CRITICAL):**
```bash
# After applying policies, WAIT 30 seconds
sleep 30
```

**2. Verify Gatekeeper is Running:**
```bash
kubectl get pods -n gatekeeper-system
# All pods should be Running
```

**3. Check Constraint Status:**
```bash
kubectl get constrainttemplates
kubectl get constraints
kubectl describe k8sblockprivileged block-privilege-escalation
```

**4. View Audit Logs:**
```bash
kubectl logs -n gatekeeper-system -l control-plane=audit-controller --tail=50
```

**5. Test Specific Policy:**
```bash
# This SHOULD be blocked
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
spec:
  containers:
  - name: test
    image: alpine
    securityContext:
      privileged: true
EOF

# Expected: Error from server (Forbidden): admission webhook denied
```

---

### Issue 5: "No Resources Found" for Constraints

**Symptoms:**
```bash
$ kubectl get constraints
No resources found
```

**Solution:**

**1. Check CRDs Installed:**
```bash
kubectl get crd | grep gatekeeper
```

**2. Reinstall Gatekeeper:**
```bash
kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.0/deploy/gatekeeper.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.0/deploy/gatekeeper.yaml
kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=5m
```

**3. Re-apply Policies:**
```bash
kubectl apply -f policies/constraint_templates/
sleep 10
kubectl apply -f policies/constraints/
```

---

## 🐛 Falco Issues

### Issue 6: Falco Not Starting

**Symptoms:**
```
helm install falco ... 
Error: unable to build kubernetes objects
```

**Solutions:**

**1. Check Kernel Version:**
```bash
uname -r
# Falco eBPF requires kernel 5.8+
```

**2. Use Modern eBPF Driver:**
```bash
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true
```

**3. If eBPF Fails, Use Kernel Module:**
```bash
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=module
```

**4. Check Falco Logs:**
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=100
```

---

## 📊 Experiment Issues

### Issue 7: Simulation Shows <100% Accuracy

**Symptoms:**
```json
{"accuracy": 85.0}  // Expected: 100.0
```

**Solutions:**

**1. Verify scikit-learn Version:**
```bash
python3 -c "import sklearn; print(sklearn.__version__)"
# Should be >= 1.3.0
```

**2. Check Training Data:**
```bash
# Ensure at least 50 scenarios for training
# Check simulation_framework_v2.py line ~80
```

**3. Re-run Simulation:**
```bash
cd scripts
./enhanced_framework_v2.sh
```

---

### Issue 8: Real K8s Tests Fail (0% Blocked)

**Symptoms:**
```
Malicious pods blocked: 0 / 100
```

**Solutions:**

**1. Verify Policies Applied:**
```bash
kubectl get constrainttemplates
kubectl get constraints

# Should show at least 4-6 constraint templates
```

**2. Check Pod Creation:**
```bash
# Try manual test
kubectl apply -f test_scenarios/malicious/privilege_escalation/privileged_pod.yaml

# Check events
kubectl get events --sort-by='.lastTimestamp' | tail -20
```

**3. Increase Sync Wait Time:**
```bash
# Edit enhanced_framework_v2.sh
# Change sleep 30 to sleep 60
```

---

### Issue 9: Results Files Missing

**Symptoms:**
```
ls results/
# Empty directory
```

**Solution:**

**1. Copy from Home Directory:**
```bash
cp ~/method*.json ~/table_*.csv ~/method4_algorithm_latex.tex results/
```

** 2. Re-run Framework:**
```bash
cd scripts
./enhanced_framework_v2.sh
```

**3. Check Permissions:**
```bash
ls -la results/
chmod 755 results/
```

---

## 💾 Resource Issues

### Issue 10: "Insufficient CPU/Memory"

**Symptoms:**
```
0/1 nodes are available: 1 Insufficient cpu, 1 Insufficient memory
```

**Solutions:**

**1. Increase Minikube Resources:**
```bash
minikube delete
minikube start --cpus=4 --memory=8192
```

**2. Reduce Pod Resource Requests:**
```yaml
# Edit test scenarios
resources:
  limits:
    cpu: 25m      # Reduced from 100m
    memory: 32Mi  # Reduced from 128Mi
```

**3. Clean Up Pods:**
```bash
kubectl delete pods --all
kubectl delete pods --field-selector=status.phase=Failed
```

---

## 🔒 Permission Issues

### Issue 11: "Forbidden: User Cannot..."

**Symptoms:**
```
Error from server (Forbidden): pods is forbidden: User "..." cannot create resource "pods"
```

**Solutions:**

**1. Check kubeconfig:**
```bash
kubectl config view
kubectl config use-context minikube
```

**2. Verify RBAC:**
```bash
kubectl auth can-i create pods
# Should return: yes
```

**3. Use Admin Context:**
```bash
# For Minikube
minikube update-context

# For K3s
sudo kubectl ...
```

---

## 📈 Performance Issues

### Issue 12: High CPU/Memory Usage

**Symptoms:**
- CPU > 50%
- Memory > 80%

**Solutions:**

**1. Reduce Test Scale:**
```bash
# Edit enhanced_framework_v2.sh
# Line 87: TOTAL_SCENARIOS=100  # Reduce to 50
```

**2. Optimize AI Models:**
```python
# In simulation code
IsolationForest(n_estimators=50)  # Reduce from 100
```

**3. Batch Processing:**
```bash
# Test in smaller batches
for i in {1..10}; do
    # Test 10 scenarios at a time
done
```

---

## 🌐 Network Issues

### Issue 13: "Dial TCP... Connection Refused"

**Symptoms:**
```
Error: dial tcp 127.0.0.1:8080: connect: connection refused
```

**Solutions:**

**1. Check API Server:**
```bash
kubectl cluster-info
minikube status
```

**2. Restart Cluster:**
```bash
minikube stop
minikube start
```

**3. Check Firewall:**
```bash
sudo ufw status
sudo ufw allow 8080/tcp
```

---

## 📝 Script Issues

### Issue 14: "Permission Denied" for Scripts

**Symptoms:**
```
bash: ./enhanced_framework_v2.sh: Permission denied
```

**Solution:**
```bash
chmod +x scripts/*.sh
./scripts/enhanced_framework_v2.sh
```

---

### Issue 15: "Command Not Found" in Script

**Symptoms:**
```
./enhanced_framework_v2.sh: line 123: python3: command not found
```

**Solution:**
```bash
# Install Python 3
sudo apt-get install python3 python3-pip

# Or use full path
/usr/bin/python3 ...
```

---

## 🔍 Debugging Tips

### Enable Verbose Logging

```bash
# For kubectl
kubectl apply -f ... -v=8

# For Gatekeeper
kubectl logs -n gatekeeper-system -l control-plane=controller-manager -f

# For Falco
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

### Check Cluster Health

```bash
kubectl get componentstatuses
kubectl get nodes -o wide
kubectl top nodes
kubectl top pods
```

### Dump Full State

```bash
kubectl cluster-info dump > cluster-dump.txt
kubectl get all --all-namespaces > all-resources.txt
```

---

## 🆘 Still Having Issues?

### Check Logs

```bash
# Kubernetes events
kubectl get events --all-namespaces --sort-by='.lastTimestamp'

# Gatekeeper audit
kubectl logs -n gatekeeper-system -l control-plane=audit-controller

# Gatekeeper controller
kubectl logs -n gatekeeper-system -l control-plane=controller-manager

# Falco alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=100
```

### Clean Install

```bash
# Complete reset
minikube delete
rm -rf ~/.minikube ~/.kube
minikube start --driver=docker --cpus=2 --memory=4096
./scripts/install_dependencies.sh
./scripts/enhanced_framework_v2.sh
```

### Get Help

- **GitHub Issues:** https://github.com/yourusername/kubernetes-devsecops-framework/issues
- **Email:** your-email@example.com
- **Include:**
  - Output of`kubectl version`
  - Output of `kubectl get pods --all-namespaces`
  - Relevant error messages
  - Steps to reproduce

---

## ✅ Verification Checklist

After troubleshooting, verify:

- [ ] Minikube/K3s running: `kubectl get nodes`
- [ ] Gatekeeper running: `kubectl get pods -n gatekeeper-system`
- [ ] Constraints active: `kubectl get constraints`
- [ ] Test policy works: Privileged pod rejected
- [ ] Results generated: `ls results/*.json`
- [ ] CPU < 20%, Memory < 30%

---

**Most issues are resolved by:**
1. ✅ Waiting 30 seconds after applying policies
2. ✅ Ensuring 2+ vCPU, 4GB+ RAM
3. ✅ Using Python 3.8+ with scikit-learn 1.3+
4. ✅ Reinstalling Gatekeeper if needed

**Good luck! 🚀**
