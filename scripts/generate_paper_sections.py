import json
import pandas as pd

with open('complete_results.json', 'r') as f:
    results = json.load(f)

print("\n" + "="*80)
print("IEEE ACCESS PAPER - READY-TO-USE CONTENT")
print("="*80)

print("\n### ABSTRACT METRICS ###")
print(f"""
The proposed unified DevSecOps framework achieved {results['overall_improvement']['overall_improvement_percentage']:.1f}% 
overall security improvement. Policy enforcement: {results['policy_enforcement']['accuracy']:.1f}% accuracy. 
Runtime detection: {results['runtime_detection']['accuracy']:.1f}% accuracy with F1={results['runtime_detection']['f1_score']:.1f}%.
""")

print("\n### TABLE 1: PERFORMANCE METRICS ###")
print(pd.read_csv('table1_metrics_summary.csv').to_string(index=False))

print("\n\n### TABLE 2: SECURITY DOMAIN IMPROVEMENTS ###")
print(pd.read_csv('table2_domain_improvements.csv').to_string(index=False))

print("\n\n### TABLE 3: RESOURCE OVERHEAD ###")
print(pd.read_csv('table3_resource_overhead.csv').to_string(index=False))

print("\n### MITRE ATT&CK COVERAGE ###")
mitre_techniques = set([s['mitre_attack_id'] for s in results['policy_enforcement']['scenarios_tested'] 
                        if s['mitre_attack_id'] is not None])
print(f"Tested {len(mitre_techniques)} MITRE ATT&CK techniques:")
for technique in sorted(mitre_techniques):
    print(f"  - {technique}")

print("\n" + "="*80)
print("FILES READY FOR YOUR IEEE ACCESS PAPER!")
print("="*80 + "\n")
