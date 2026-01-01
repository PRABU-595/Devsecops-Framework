"""
PSOA: Policy Synthesis & Optimization Algorithm
=================================================

Generates optimized OPA Rego policies from threat model using Pareto optimization.

Algorithm Complexity: O(p log p) where p = number of policies
Space Complexity: O(p)

Author: Prabu, Divya, Vijayalakshmi  
Paper: "A Unified DevSecOps Framework for Policy-Driven and AI-Augmented Cloud-Native Security"
"""

import logging
from dataclasses import dataclass
from typing import List, Dict, Set, Tuple, Optional
from enum import Enum
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PolicyPriority(Enum):
    """Policy priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class PolicyRule:
    """OPA Rego policy rule"""
    rule_id: str
    name: str
    rego_code: str
    priority: PolicyPriority
    mitre_technique: str
    fpr_estimate: float  # Estimated false positive rate
    latency_estimate: float  # Estimated decision latency (ms)
    coverage: Set[str]  # Set of threat node IDs covered
    
    def __hash__(self):
        return hash(self.rule_id)


class RegoGenerator:
    """Generates OPA Rego policy code"""
    
    @staticmethod
    def generate_block_privileged() -> str:
        """Generate Rego policy to block privileged containers"""
        return """
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Privileged container not allowed: %v (MITRE T1068)", [container.name])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.initContainers[_]
    container.securityContext.privileged == true
    msg := sprintf("Privileged init container not allowed: %v (MITRE T1068)", [container.name])
}
"""
    
    @staticmethod
    def generate_block_host_namespace() -> str:
        """Generate Rego policy to block host namespace sharing"""
        return """
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.hostPID == true
    msg := "hostPID not allowed (MITRE T1611 - Container Escape)"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.hostNetwork == true
    msg := "hostNetwork not allowed (MITRE T1611 - Container Escape)"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.hostIPC == true
    msg := "hostIPC not allowed (MITRE T1611 - Container Escape)"
}
"""
    
    @staticmethod
    def generate_block_capabilities(dangerous_caps: List[str]) -> str:
        """Generate Rego policy to block dangerous Linux capabilities"""
        caps_array = json.dumps(dangerous_caps)
        return f"""
package kubernetes.admission

forbidden_capabilities := {caps_array}

deny[msg] {{
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    cap := container.securityContext.capabilities.add[_]
    cap_upper := upper(cap)
    forbidden_capabilities[_] == cap_upper
    msg := sprintf("Capability %v not allowed on container %v (MITRE T1068)", [cap, container.name])
}}
"""
    
    @staticmethod
    def generate_require_resources() -> str:
        """Generate Rego policy to require resource limits"""
        return """
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits
    msg := sprintf("Container %v must have resource limits (MITRE T1496 - Resource Hijacking)", [container.name])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.requests
    msg := sprintf("Container %v must have resource requests (MITRE T1496)", [container.name])
}
"""
    
    @staticmethod
    def generate_block_hostpath() -> str:
        """Generate Rego policy to block hostPath volumes"""
        return """
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    volume := input.request.object.spec.volumes[_]
    volume.hostPath
    msg := sprintf("hostPath volume not allowed: %v (MITRE T1611 - Container Escape)", [volume.name])
}
"""


class ConflictResolver:
    """Resolves conflicts between policies"""
    
    @staticmethod
    def detect_conflicts(policies: List[PolicyRule]) -> List[Tuple[PolicyRule, PolicyRule]]:
        """
        Detect conflicting policies.
        Two policies conflict if they:
        1. Have overlapping coverage but contradictory rules
        2. Are both critical priority but mutually exclusive
        """
        conflicts = []
        
        for i, p1 in enumerate(policies):
            for p2 in policies[i+1:]:
                # Check for overlapping coverage
                overlap = p1.coverage & p2.coverage
                if overlap:
                    # Simple heuristic: if both are critical and have similar names, might conflict
                    if (p1.priority == PolicyPriority.CRITICAL and 
                        p2.priority == PolicyPriority.CRITICAL):
                        if self._names_conflict(p1.name, p2.name):
                            conflicts.append((p1, p2))
        
        return conflicts
    
    @staticmethod
    def _names_conflict(name1: str, name2: str) -> bool:
        """Check if policy names suggest a conflict"""
        # Simple heuristic - in production, use semantic analysis
        keywords = ['allow', 'deny', 'block', 'require']
        return any(k in name1.lower() and k in name2.lower() for k in keywords)
    
    @staticmethod
    def resolve(p1: PolicyRule, p2: PolicyRule) -> PolicyRule:
        """
        Resolve conflict between two policies.
        Strategy: Keep the more specific (higher priority, lower FPR) policy
        """
        if p1.priority.value < p2.priority.value:
            return p1
        elif p2.priority.value < p1.priority.value:
            return p2
        else:
            # Same priority - choose lower FPR
            return p1 if p1.fpr_estimate < p2.fpr_estimate else p2


class ParetoOptimizer:
    """Multi-objective Pareto optimization for policies"""
    
    @staticmethod
    def pareto_frontier(policies: List[PolicyRule]) -> List[PolicyRule]:
        """
        Compute Pareto frontier: policies that minimize both FPR and latency.
        
        A policy is Pareto optimal if no other policy is better in both objectives.
        
        Time Complexity: O(p log p) where p = number of policies
        """
        if not policies:
            return []
        
        # Sort by FPR first
        sorted_policies = sorted(policies, key=lambda p: (p.fpr_estimate, p.latency_estimate))
        
        frontier = [sorted_policies[0]]
        min_latency = sorted_policies[0].latency_estimate
        
        for policy in sorted_policies[1:]:
            # Add to frontier if it improves latency (since FPR is already sorted)
            if policy.latency_estimate < min_latency:
                frontier.append(policy)
                min_latency = policy.latency_estimate
        
        logger.info(f"Pareto optimization: {len(policies)} -> {len(frontier)} policies")
        return frontier
    
    @staticmethod
    def rank_by_efficiency(policies: List[PolicyRule]) -> List[PolicyRule]:
        """
        Rank policies by efficiency score.
        Efficiency = Coverage / (FPR * Latency)
        """
        def efficiency_score(p: PolicyRule) -> float:
            coverage_size = len(p.coverage)
            penalty = max(p.fpr_estimate, 0.01) * max(p.latency_estimate, 1.0)
            return coverage_size / penalty
        
        return sorted(policies, key=efficiency_score, reverse=True)


class PolicySynthesizer:
    """Main PSOA engine - synthesizes and optimizes policies"""
    
    def __init__(self):
        self.rego_gen = RegoGenerator()
        self.conflict_resolver = ConflictResolver()
        self.pareto_optimizer = ParetoOptimizer()
        self.policy_catalog: List[PolicyRule] = []
        
    def synthesize_from_threat_graph(self, threat_graph) -> List[PolicyRule]:
        """
        Generate policies from threat graph.
        
        Args:
            threat_graph: ThreatGraph from CTMRA
            
        Returns:
            List of synthesized PolicyRule objects
            
        Time Complexity: O(n) where n = high-risk nodes
        """
        policies = []
        high_risk_nodes = threat_graph.get_high_risk_nodes(threshold=10.0)
        
        logger.info(f"Synthesizing policies for {len(high_risk_nodes)} high-risk nodes")
        
        # Map threat characteristics to policies
        needs_privileged_block = False
        needs_host_ns_block = False
        needs_capability_block = False
        needs_resources_policy = False
        needs_hostpath_block = False
        
        dangerous_capabilities = set()
        
        for node in high_risk_nodes:
            # Check what types of threats are present
            if 'privileged' in node.name.lower() or 'T1068' in node.node_id:
                needs_privileged_block = True
            
            if 'escape' in node.name.lower() or 'T1611' in node.node_id or 'host' in node.node_type:
                needs_host_ns_block = True
                needs_hostpath_block = True
            
            if 'capability' in node.name.lower() or 'cap' in node.node_type:
                needs_capability_block = True
                dangerous_capabilities.update(['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE'])
            
            if 'resource' in node.name.lower() or 'T1496' in node.node_id:
                needs_resources_policy = True
        
        # Generate policies based on detected threats
        policy_id = 1
        
        if needs_privileged_block:
            policies.append(PolicyRule(
                rule_id=f"policy-{policy_id}",
                name="Block Privileged Containers",
                rego_code=self.rego_gen.generate_block_privileged(),
                priority=PolicyPriority.CRITICAL,
                mitre_technique="T1068",
                fpr_estimate=0.01,
                latency_estimate=5.0,
                coverage={'T1068-PrivilegeEscalation'}
            ))
            policy_id += 1
        
        if needs_host_ns_block:
            policies.append(PolicyRule(
                rule_id=f"policy-{policy_id}",
                name="Block Host Namespace Sharing",
                rego_code=self.rego_gen.generate_block_host_namespace(),
                priority=PolicyPriority.CRITICAL,
                mitre_technique="T1611",
                fpr_estimate=0.02,
                latency_estimate=6.0,
                coverage={'T1611-EscapeToHost'}
            ))
            policy_id += 1
        
        if needs_capability_block:
            policies.append(PolicyRule(
                rule_id=f"policy-{policy_id}",
                name="Block Dangerous Capabilities",
                rego_code=self.rego_gen.generate_block_capabilities(list(dangerous_capabilities)),
                priority=PolicyPriority.HIGH,
                mitre_technique="T1068",
                fpr_estimate=0.03,
                latency_estimate=4.5,
                coverage={'T1068-CapabilityAbuse'}
            ))
            policy_id += 1
        
        if needs_resources_policy:
            policies.append(PolicyRule(
                rule_id=f"policy-{policy_id}",
                name="Require Resource Limits",
                rego_code=self.rego_gen.generate_require_resources(),
                priority=PolicyPriority.MEDIUM,
                mitre_technique="T1496",
                fpr_estimate=0.05,
                latency_estimate=3.0,
                coverage={'T1496-ResourceHijacking'}
            ))
            policy_id += 1
        
        if needs_hostpath_block:
            policies.append(PolicyRule(
                rule_id=f"policy-{policy_id}",
                name="Block HostPath Volumes",
                rego_code=self.rego_gen.generate_block_hostpath(),
                priority=PolicyPriority.CRITICAL,
                mitre_technique="T1611",
                fpr_estimate=0.01,
                latency_estimate=4.0,
                coverage={'T1611-HostPathEscape'}
            ))
        
        self.policy_catalog = policies
        logger.info(f"✅ Synthesized {len(policies)} policies")
        return policies
    
    def optimize_policies(self, policies: List[PolicyRule], 
                         business_constraints: Optional[Dict] = None) -> List[PolicyRule]:
        """
        Optimize policies using Pareto frontier and conflict resolution.
        
        Args:
            policies: List of candidate policies
            business_constraints: Optional constraints (e.g., max latency, max FPR)
            
        Returns:
            Optimized policy set
            
        Time Complexity: O(p log p)
        """
        logger.info(f"Optimizing {len(policies)} policies...")
        
        # Step 1: Detect and resolve conflicts
        conflicts = self.conflict_resolver.detect_conflicts(policies)
        if conflicts:
            logger.warning(f"Found {len(conflicts)} policy conflicts, resolving...")
            for p1, p2 in conflicts:
                winner = self.conflict_resolver.resolve(p1, p2)
                loser = p2 if winner == p1 else p1
                if loser in policies:
                    policies.remove(loser)
                    logger.info(f"   Removed conflicting policy: {loser.name}")
        
        # Step 2: Pareto optimization
        pareto_policies = self.pareto_optimizer.pareto_frontier(policies)
        
        # Step 3: Apply business constraints
        if business_constraints:
            max_fpr = business_constraints.get('max_fpr', 1.0)
            max_latency = business_constraints.get('max_latency', 100.0)
            
            pareto_policies = [
                p for p in pareto_policies
                if p.fpr_estimate <= max_fpr and p.latency_estimate <= max_latency
            ]
            logger.info(f"Applied business constraints: {len(pareto_policies)} policies remain")
        
        # Step 4: Rank by efficiency
        optimized = self.pareto_optimizer.rank_by_efficiency(pareto_policies)
        
        logger.info(f"✅ Optimized to {len(optimized)} policies")
        return optimized
    
    def export_opa_bundle(self, policies: List[PolicyRule], output_dir: str):
        """Export policies as OPA bundle"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        for policy in policies:
            filename = f"{policy.rule_id}.rego"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w') as f:
                f.write(policy.rego_code)
            logger.info(f"Exported policy: {filepath}")
        
        # Create bundle manifest
        manifest = {
            'roots': ['kubernetes/admission'],
            'metadata': {
                'generated_by': 'PSOA',
                'policy_count': len(policies),
                'timestamp': str(datetime.now())
            }
        }
        
        with open(os.path.join(output_dir, '.manifest'), 'w') as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"✅ OPA bundle exported to {output_dir}")


# Example usage
if __name__ == "__main__":
    from ctmra import ThreatModeler
    from datetime import datetime
    
    # Example: Synthesize policies from threat model
    manifest = {
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {'name': 'malicious-pod'},
        'spec': {
            'hostPID': True,
            'containers': [{
                'name': 'attacker',
                'image': 'nginx:latest',
                'securityContext': {
                    'privileged': True,
                    'capabilities': {'add': ['SYS_ADMIN']}
                }
            }]
        }
    }
    
    # Step 1: Threat modeling
    threat_modeler = ThreatModeler()
    threat_graph = threat_modeler.analyze_manifest(manifest)
    
    # Step 2: Policy synthesis
    synthesizer = PolicySynthesizer()
    policies = synthesizer.synthesize_from_threat_graph(threat_graph)
    
    # Step 3: Optimization
    business_constraints = {
        'max_fpr': 0.05,
        'max_latency': 50.0
    }
    optimized_policies = synthesizer.optimize_policies(policies, business_constraints)
    
    # Step 4: Export
    synthesizer.export_opa_bundle(optimized_policies, 'opa-policies/')
    
    print(f"\n✅ PSOA complete!")
    print(f"   Synthesized: {len(policies)} policies")
    print(f"   Optimized: {len(optimized_policies)} policies")
    print(f"   Exported to: opa-policies/")
