#!/bin/bash
################################################################################
# Cleanup Script for Kubernetes DevSecOps Framework
# Removes all deployed resources and optionally deletes the cluster
################################################################################

set -e

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║   Kubernetes DevSecOps Framework - Cleanup                                ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Cannot perform cleanup."
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    echo "⚠️  No Kubernetes cluster found or inaccessible."
    echo ""
    read -p "Delete Minikube cluster anyway? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v minikube &> /dev/null; then
            minikube delete
            echo "✅ Minikube cluster deleted"
        fi
    fi
    exit 0
fi

echo "🔍 Found Kubernetes cluster: $(kubectl config current-context)"
echo ""

# Function to delete resources in a namespace
delete_namespace_resources() {
    local ns=$1
    echo "🗑️  Cleaning namespace: $ns"
    
    # Delete all pods
    kubectl delete pods --all -n "$ns" --force --grace-period=0 2>/dev/null || true
    
    # Delete deployments
    kubectl delete deployments --all -n "$ns" 2>/dev/null || true
    
    # Delete daemonsets
    kubectl delete daemonsets --all -n "$ns" 2>/dev/null || true
    
    # Delete services
    kubectl delete services --all -n "$ns" 2>/dev/null || true
    
    echo "   ✅ Namespace $ns cleaned"
}

# Clean default namespace
delete_namespace_resources "default"

# Clean Gatekeeper
echo ""
echo "🗑️  Removing OPA Gatekeeper..."
kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.0/deploy/gatekeeper.yaml --ignore-not-found 2>/dev/null || true
kubectl delete namespace gatekeeper-system --ignore-not-found 2>/dev/null || true
echo "   ✅ OPA Gatekeeper removed"

# Clean Falco
echo ""
echo "🗑️  Removing Falco..."
if command -v helm &> /dev/null; then
    helm uninstall falco -n falco 2>/dev/null || true
    kubectl delete namespace falco --ignore-not-found 2>/dev/null || true
    echo "   ✅ Falco removed"
else
    echo "   ⚠️  Helm not found, skipping Falco cleanup"
fi

# Remove generated test files
echo ""
echo "🗑️  Removing generated test files..."
rm -f malicious_100_tests.yaml benign_100_tests.yaml 2>/dev/null || true
rm -f generate_100_scenarios.py 2>/dev/null || true
rm -f simulation_framework_v2.py 2>/dev/null || true
rm -f baseline_comparison.py 2>/dev/null || true
rm -f novel_algorithms.py 2>/dev/null || true
rm -f comprehensive_analysis.py 2>/dev/null || true
echo "   ✅ Generated files removed"

# Remove result files (optional)
echo ""
read -p "❓ Delete result files (*.json, *.csv, *.tex)? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f method*.json table_*.csv *.tex 2>/dev/null || true
    echo "   ✅ Result files deleted"
else
    echo "   ⏭️  Result files preserved"
fi

# Ask about cluster deletion
echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║   Cluster Deletion Options                                                ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Choose an option:"
echo "  1) Stop Minikube (preserves cluster state)"
echo "  2) Delete Minikube completely"
echo "  3) Keep cluster running"
echo ""
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        if command -v minikube &> /dev/null; then
            minikube stop
            echo "✅ Minikube stopped (run 'minikube start' to resume)"
        else
            echo "⚠️  Minikube not found"
        fi
        ;;
    2)
        if command -v minikube &> /dev/null; then
            minikube delete
            echo "✅ Minikube cluster deleted"
        else
            echo "⚠️  Minikube not found"
        fi
        ;;
    3)
        echo "✅ Cluster left running"
        ;;
    *)
        echo "⚠️  Invalid choice. Cluster left running."
        ;;
esac

echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║   ✅ Cleanup Complete!                                                     ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 What was cleaned:"
echo "   ✅ All pods in default namespace"
echo "   ✅ OPA Gatekeeper and policies"
echo "   ✅ Falco runtime security"
echo "   ✅ Generated test files"
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "   ✅ Result files"
fi
echo ""
echo "To re-run the framework:"
echo "   cd scripts && ./enhanced_framework_v2.sh"
echo ""
