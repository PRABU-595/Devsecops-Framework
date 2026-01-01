# Figures

Place your paper figures here:

1. **architecture_diagram.png** - Framework architecture (Fig. 1 from paper)
2. **performance_comparison.png** - Detection accuracy comparison (Table III)
3. **scalability_results.png** - Latency vs workload size (Table VII)

## Generating Figures

### From Python:
```python
import matplotlib.pyplot as plt
import json

# Load results
with open('../results/method3_baseline_comparison.json') as f:
    data = json.load(f)

# Create bar chart
frameworks = ['Our Framework', 'Aqua', 'Sysdig', 'Wiz', 'OPA+Falco']
accuracies = [100.0, 84.5, 81.3, 79.5, 76.9]

plt.bar(frameworks, accuracies)
plt.ylabel('Detection Accuracy (%)')
plt.title('Framework Comparison')
plt.ylim([70, 105])
plt.savefig('performance_comparison.png', dpi=300)
```

### From Paper:
Export figures from your IEEE TCC LaTeX paper as PNG (300 DPI).
