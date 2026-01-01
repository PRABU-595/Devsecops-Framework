"""
CTMRA: Continuous Threat Modeling & Risk Assessment
====================================================

Monitors Kubernetes cluster, builds threat graph, computes risk scores.

Algorithm Complexity: O(n + m) where n = containers, m = edges
Space Complexity: O(n + m)

Author: Prabu, Divya, Vijayalakshmi
Paper: "A Unified DevSecOps Framework for Policy-Driven and AI-Augmented Cloud-Native Security"
"""

import networkx as nx
import requests
import logging
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """CVE vulnerability information"""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    affected_versions: List[str]


@dataclass
class ThreatNode:
    """Node in threat graph"""
    node_id: str
    node_type: str  # 'container', 'service', 'volume', 'secret'
    name: str
    image: Optional[str] = None
    risk_score: float = 0.0
    vulnerabilities: List[Vulnerability] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


class CVEQueryEngine:
    """Query CVE databases for vulnerabilities"""
    
    def __init__(self, nist_api_key: Optional[str] = None):
        self.nist_api_key = nist_api_key
        self.cache = {}  # Simple caching
        
    def query_image_vulnerabilities(self, image: str) -> List[Vulnerability]:
        """
        Query vulnerabilities for a container image.
        
        In production, this would:
        1. Parse image name and tag
        2. Query vulnerability databases (NIST NVD, Trivy, Grype)
        3. Return list of CVEs
        
        For now, returns simulated vulnerabilities based on image characteristics.
        """
        if image in self.cache:
            return self.cache[image]
        
        vulns = []
        
        # Heuristic-based risk assessment (replace with real CVE API in production)
        if any(tag in image.lower() for tag in ['latest', 'dev', 'debug']):
            vulns.append(Vulnerability(
                cve_id="CVE-2024-XXXX",
                cvss_score=7.5,
                severity="HIGH",
                description="Unversioned image tag increases supply chain risk",
                affected_versions=["latest"]
            ))
        
        if 'alpine' not in image.lower() and 'distroless' not in image.lower():
            vulns.append(Vulnerability(
                cve_id="CVE-2023-YYYY",
                cvss_score=5.3,
                severity="MEDIUM",
                description="Large image attack surface",
                affected_versions=["*"]
            ))
        
        self.cache[image] = vulns
        return vulns
    
    def query_nist_nvd(self, cpe: str) -> List[Vulnerability]:
        """Query NIST NVD API (production implementation)"""
        # TODO: Implement actual NIST NVD API integration
        # API: https://services.nvd.nist.gov/rest/json/cves/2.0
        pass


class ThreatGraph:
    """Threat graph data structure"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, ThreatNode] = {}
        
    def add_node(self, node: ThreatNode):
        """Add node to threat graph"""
        self.nodes[node.node_id] = node
        self.graph.add_node(node.node_id, **node.__dict__)
        
    def add_edge(self, src: str, dst: str, weight: float, edge_type: str):
        """Add weighted edge (e.g., network communication, volume mount)"""
        self.graph.add_edge(src, dst, weight=weight, edge_type=edge_type)
        
    def compute_risk_scores(self):
        """
        Compute risk scores for all nodes based on:
        1. Direct vulnerabilities (CVSS scores)
        2. Incoming edge weights (transitive risk)
        3. Node centrality (exposure)
        """
        for node_id, node in self.nodes.items():
            # Direct vulnerability risk
            direct_risk = sum(v.cvss_score for v in node.vulnerabilities)
            
            # Transitive risk from incoming edges
            transitive_risk = sum(
                self.graph[pred][node_id]['weight']
                for pred in self.graph.predecessors(node_id)
            ) if self.graph.has_node(node_id) else 0
            
            # Centrality-based risk (highly connected nodes are riskier)
            centrality = nx.degree_centrality(self.graph).get(node_id, 0)
            centrality_risk = centrality * 10  # Scale factor
            
            # Combined risk score
            node.risk_score = direct_risk + transitive_risk + centrality_risk
            
    def get_high_risk_nodes(self, threshold: float = 3.0) -> List[ThreatNode]:
        """Return nodes with risk score above threshold"""
        return [node for node in self.nodes.values() if node.risk_score > threshold]
    
    def to_dict(self) -> dict:
        """Export graph to dictionary"""
        return {
            'nodes': {nid: node.__dict__ for nid, node in self.nodes.items()},
            'edges': list(self.graph.edges(data=True))
        }


class ThreatModeler:
    """Main CTMRA engine"""
    
    def __init__(self, cve_engine: Optional[CVEQueryEngine] = None):
        self.cve_engine = cve_engine or CVEQueryEngine()
        self.threat_graph = ThreatGraph()
        
    def analyze_manifest(self, manifest: dict) -> ThreatGraph:
        """
        Analyze a Kubernetes manifest and build threat graph.
        
        Args:
            manifest: Kubernetes Pod/Deployment manifest
            
        Returns:
            ThreatGraph with risk scores computed
            
        Time Complexity: O(n + m) where n = containers, m = communication edges
        """
        kind = manifest.get('kind', 'Pod')
        metadata = manifest.get('metadata', {})
        spec = manifest.get('spec', {})
        
        # Extract pod spec (handle Deployment, Pod, etc.)
        if kind == 'Deployment':
            pod_spec = spec.get('template', {}).get('spec', {})
        else:
            pod_spec = spec
            
        # Analyze containers
        containers = pod_spec.get('containers', []) + pod_spec.get('initContainers', [])
        
        for idx, container in enumerate(containers):
            container_id = f"{metadata.get('name', 'unknown')}-container-{idx}"
            image = container.get('image', 'unknown')
            
            # Query vulnerabilities
            vulns = self.cve_engine.query_image_vulnerabilities(image)
            
            # Create threat node
            node = ThreatNode(
                node_id=container_id,
                node_type='container',
                name=container.get('name', f'container-{idx}'),
                image=image,
                vulnerabilities=vulns
            )
            
            self.threat_graph.add_node(node)
            
            # Analyze security context risks
            sec_ctx = container.get('securityContext', {})
            if sec_ctx.get('privileged'):
                # Add high-risk edge for privilege escalation
                self.threat_graph.add_edge(
                    container_id, 'T1068-PrivilegeEscalation',
                    weight=9.0, edge_type='attack_path'
                )
            
            if sec_ctx.get('capabilities', {}).get('add'):
                caps = sec_ctx['capabilities']['add']
                dangerous_caps = {'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE'}
                if any(cap in dangerous_caps for cap in caps):
                    self.threat_graph.add_edge(
                        container_id, 'T1068-CapabilityAbuse',
                        weight=7.5, edge_type='attack_path'
                    )
        
        # Analyze host namespace sharing
        if pod_spec.get('hostPID') or pod_spec.get('hostNetwork') or pod_spec.get('hostIPC'):
            node = ThreatNode(
                node_id='T1611-EscapeToHost',
                node_type='attack_technique',
                name='Container Escape',
                risk_score=8.5
            )
            self.threat_graph.add_node(node)
        
        # Analyze volumes
        volumes = pod_spec.get('volumes', [])
        for vol in volumes:
            if 'hostPath' in vol:
                vol_node = ThreatNode(
                    node_id=f"volume-{vol['name']}",
                    node_type='volume',
                    name=vol['name'],
                    risk_score=8.0  # hostPath is high risk
                )
                self.threat_graph.add_node(vol_node)
        
        # Compute risk scores
        self.threat_graph.compute_risk_scores()
        
        logger.info(f"Analyzed manifest: {len(self.threat_graph.nodes)} nodes, "
                   f"{len(self.threat_graph.graph.edges)} edges")
        
        return self.threat_graph
    
    def continuous_monitoring(self, k8s_client, interval: int = 60):
        """
        Continuously monitor Kubernetes cluster for changes.
        
        In production, this would:
        1. Watch Kubernetes API for pod create/update/delete events
        2. Rebuild threat graph incrementally
        3. Trigger policy updates when high-risk changes detected
        """
        # TODO: Implement using Kubernetes watch API
        pass
    
    def export_threat_report(self, filepath: str):
        """Export threat analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_nodes': len(self.threat_graph.nodes),
            'total_edges': len(self.threat_graph.graph.edges),
            'high_risk_nodes': [
                node.__dict__ for node in self.threat_graph.get_high_risk_nodes()
            ],
            'graph': self.threat_graph.to_dict()
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Threat report exported to {filepath}")


# Example usage
if __name__ == "__main__":
    # Example manifest
    manifest = {
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {'name': 'test-pod'},
        'spec': {
            'containers': [{
                'name': 'app',
                'image': 'nginx:latest',
                'securityContext': {
                    'privileged': True
                }
            }]
        }
    }
    
    # Analyze
    modeler = ThreatModeler()
    threat_graph = modeler.analyze_manifest(manifest)
    
    # Export
    modeler.export_threat_report('threat_analysis.json')
    
    print(f"✅ Threat modeling complete!")
    print(f"   High-risk nodes: {len(threat_graph.get_high_risk_nodes())}")
    for node in threat_graph.get_high_risk_nodes():
        print(f"   - {node.name}: Risk={node.risk_score:.1f}")
