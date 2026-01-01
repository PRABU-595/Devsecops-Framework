#!/bin/bash
################################################################################
# Quick Setup Helper - Copies results and makes scripts executable
################################################################################

echo "🚀 Kubernetes DevSecOps Framework - Quick Setup"
echo "================================================"
echo ""

REPO_DIR="C:/Users/iampr/Desktop/MY PAPERS/1.Cloud-Native Security A Deep Dive into Risks, Solutions, and Future Trends/kubernetes-devsecops-framework"
HOME_DIR=~

echo "📁 Repository: $REPO_DIR"
echo "📁 Home directory: $HOME_DIR"
echo ""

# Make scripts executable
echo "🔧 Making scripts executable..."
chmod +x "$REPO_DIR/scripts"/*.sh 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ Scripts are now executable"
else
    echo "   ⚠️  Could not make scripts executable (may need sudo)"
fi
echo ""

# Copy results if they exist
echo "📋 Copying result files..."
results_copied=0

result_files=(
    "method1_simulation_results.json"
    "method2_real_results.json"
    "method3_baseline_comparison.json"
    "method4_novel_algorithms.json"
    "method5_final_report.json"
    "table_iii_comprehensive.csv"
    "method4_algorithm_latex.tex"
)

for file in "${result_files[@]}"; do
    if [ -f "$HOME_DIR/$file" ]; then
        cp "$HOME_DIR/$file" "$REPO_DIR/results/" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "   ✅ Copied $file"
            ((results_copied++))
        else
            echo "   ❌ Failed to copy $file"
        fi
    else
        echo "   ⏭️  $file not found (run enhanced_framework_v2.sh first)"
    fi
done

echo ""
echo "📊 Summary:"
echo "   Results copied: $results_copied / ${#result_files[@]}"
echo ""

# Show next steps
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   ✅ Quick Setup Complete!                                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 What's Done:"
echo "   ✅ Scripts are executable"
if [ $results_copied -gt 0 ]; then
    echo "   ✅ $results_copied result files copied"
fi
echo ""
echo "📋 Next Steps:"
if [ $results_copied -eq 0 ]; then
    echo "   1. Run the framework to generate results:"
    echo "      cd $REPO_DIR/scripts"
    echo "      ./enhanced_framework_v2.sh"
    echo ""
fi
echo "   2. Create documentation files (see PROJECT_STATUS.md)"
echo "   3. Add policy templates and test scenarios"
echo "   4. Generate figures from results"
echo "   5. Push to GitHub and share!"
echo ""
echo "📖 Read PROJECT_STATUS.md for detailed next steps"
echo ""
