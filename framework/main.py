"""
Unified DevSecOps Framework - Main Integration
===============================================

Integrates all 4 core algorithms: CTMRA, PSOA, ASOA, IADRA

Usage:
    python -m framework.main --manifest pod.yaml
    python -m framework.main --watch --namespace default

Author: Prabu, Divya, Vijayalakshmi
"""

import asyncio
import argparse
import logging
from pathlib import Path
from datetime import datetime
import yaml

from framework.core.ctmra import ThreatModeler, CVEQueryEngine
from framework.core.psoa import PolicySynthesizer
from framework.core.asoa import SecurityOrchestrator, SecurityEvent
from framework.core.iadra import AnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class UnifiedFramework:
    """Main framework integrating all components"""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        # Initialize components
        logger.info("Initializing Unified DevSecOps Framework...")
        
        self.cve_engine = CVEQueryEngine()
        self.threat_modeler = ThreatModeler(self.cve_engine)
        self.policy_synthesizer = PolicySynthesizer()
        self.orchestrator = SecurityOrchestrator()
        self.anomaly_detector = AnomalyDetector()
        
        logger.info("✅ Framework initialized")
    
    async def analyze_manifest(self, manifest: dict) -> dict:
        """
        Full pipeline: Threat modeling -> Policy synthesis -> Orchestrated evaluation
        
        Returns:
            Comprehensive security assessment
        """
        logger.info("="*60)
        logger.info("UNIFIED DEVSECOPS FRAMEWORK - ANALYSIS PIPELINE")
        logger.info("="*60)
        
        # Phase 1: CTMRA - Threat Modeling
        logger.info("\n[1/4] CTMRA: Threat Modeling & Risk Assessment")
        threat_graph = self.threat_modeler.analyze_manifest(manifest)
        high_risk_nodes = threat_graph.get_high_risk_nodes()
        logger.info(f"   ✅ Identified {len(high_risk_nodes)} high-risk nodes")
        
        # Phase 2: PSOA - Policy Synthesis
        logger.info("\n[2/4] PSOA: Policy Synthesis & Optimization")
        policies = self.policy_synthesizer.synthesize_from_threat_graph(threat_graph)
        optimized_policies = self.policy_synthesizer.optimize_policies(
            policies,
            business_constraints={'max_fpr': 0.05, 'max_latency': 50.0}
        )
        logger.info(f"   ✅ Synthesized {len(policies)} policies, optimized to {len(optimized_policies)}")
        
        # Phase 3: IADRA - AI Anomaly Detection
        logger.info("\n[3/4] IADRA: AI Anomaly Detection")
        anomaly_result = self.anomaly_detector.detect_anomaly(manifest)
        logger.info(f"   ✅ Anomaly: {anomaly_result.is_anomaly} "
                   f"(Type: {anomaly_result.anomaly_type.value}, "
                   f"Confidence: {anomaly_result.confidence:.2%})")
        
        # Phase 4: ASOA - Orchestrated Decision
        logger.info("\n[4/4] ASOA: Security Orchestration")
        event = SecurityEvent(
            event_id="analysis-001",
            event_type="pod_create",
            timestamp=datetime.now(),
            resource_kind=manifest.get('kind', 'Pod'),
            resource_name=manifest.get('metadata', {}).get('name', 'unknown'),
            manifest=manifest
        )
        
        final_decision = await self.orchestrator.evaluate_event(event)
        logger.info(f"   ✅ Decision: {final_decision.decision.value} "
                   f"(Confidence: {final_decision.confidence:.2%})")
        
        # Compile results
        logger.info("\n" + "="*60)
        logger.info("ANALYSIS COMPLETE")
        logger.info("="*60)
        
        return {
            'ctmra': {
                'total_nodes': len(threat_graph.nodes),
                'high_risk_nodes': len(high_risk_nodes),
                'max_risk_score': max([n.risk_score for n in high_risk_nodes]) if high_risk_nodes else 0
            },
            'psoa': {
                'policies_generated': len(policies),
                'policies_optimized': len(optimized_policies),
                'estimated_fpr': sum(p.fpr_estimate for p in optimized_policies) / len(optimized_policies) if optimized_policies else 0
            },
            'iadra': {
                'is_anomaly': anomaly_result.is_anomaly,
                'anomaly_type': anomaly_result.anomaly_type.value,
                'confidence': anomaly_result.confidence,
                'recommended_action': anomaly_result.recommended_action
            },
            'asoa': {
                'final_decision': final_decision.decision.value,
                'confidence': final_decision.confidence,
                'latency_ms': final_decision.latency_ms,
                'reason': final_decision.reason
            }
        }
    
    def export_policies(self, output_dir: str = "./opa-policies"):
        """Export synthesized OPA policies"""
        logger.info(f"Exporting policies to {output_dir}...")
        self.policy_synthesizer.export_opa_bundle(
            self.policy_synthesizer.policy_catalog,
            output_dir
        )


async def main():
    parser = argparse.ArgumentParser(description="Unified DevSecOps Framework")
    parser.add_argument('--manifest', type=str, help="Path to Kubernetes manifest YAML")
    parser.add_argument('--watch', action='store_true', help="Watch Kubernetes cluster")
    parser.add_argument('--namespace', type=str, default='default', help="Namespace to watch")
    parser.add_argument('--export-policies', type=str, help="Export OPA policies to directory")
    
    args = parser.parse_args()
    
    framework = UnifiedFramework()
    
    if args.manifest:
        # Analyze single manifest
        with open(args.manifest) as f:
            manifest = yaml.safe_load(f)
        
        result = await framework.analyze_manifest(manifest)
        
        print("\n" + "="*60)
        print("SECURITY ASSESSMENT SUMMARY")
        print("="*60)
        print(f"\nCTMRA (Threat Modeling):")
        print(f"  High-risk nodes: {result['ctmra']['high_risk_nodes']}")
        print(f"  Max risk score: {result['ctmra']['max_risk_score']:.1f}")
        
        print(f"\nPSOA (Policy Synthesis):")
        print(f"  Policies optimized: {result['psoa']['policies_optimized']}")
        print(f"  Estimated FPR: {result['psoa']['estimated_fpr']:.2%}")
        
        print(f"\nIADRA (AI Detection):")
        print(f"  Anomaly detected: {result['iadra']['is_anomaly']}")
        print(f"  Type: {result['iadra']['anomaly_type']}")
        print(f"  Recommended Action: {result['iadra']['recommended_action']}")
        
        print(f"\nASOA (Final Decision):")
        print(f"  Decision: {result['asoa']['final_decision']}")
        print(f"  Confidence: {result['asoa']['confidence']:.2%}")
        print(f"  Latency: {result['asoa']['latency_ms']:.1f}ms")
        print(f"  Reason: {result['asoa']['reason']}")
        print("="*60)
    
    elif args.export_policies:
        framework.export_policies(args.export_policies)
        print(f"✅ Policies exported to {args.export_policies}")
    
    elif args.watch:
        print(f"🔍 Watching namespace: {args.namespace}")
        print("   (Continuous monitoring not yet implemented)")
        # TODO: Implement Kubernetes watch API integration
    
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
