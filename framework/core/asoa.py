"""
ASOA: Adaptive Security Orchestration Algorithm
=================================================

Coordinates OPA, Falco, and AI-driven anomaly detection with dynamic adaptation.

Algorithm Complexity: O(t log t + n) where t =tools, n = events
Space Complexity: O(t + n)

Author: Prabu, Divya, Vijayalakshmi
Paper: "A Unified DevSecOps Framework for Policy-Driven and AI-Augmented Cloud-Native Security"
"""

import logging
from dataclasses import dataclass
from typing import List, Dict, Optional, Callable
from enum import Enum
from datetime import datetime
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Decision(Enum):
    """Security decision types"""
    ALLOW = "allow"
    BLOCK = "block"
    ALERT = "alert"
    UNKNOWN = "unknown"


@dataclass
class SecurityEvent:
    """Security event to be evaluated"""
    event_id: str
    event_type: str  # 'pod_create', 'pod_update', 'network_connection', etc.
    timestamp: datetime
    resource_kind: str
    resource_name: str
    manifest: Optional[Dict] = None
    metadata: Optional[Dict] = None


@dataclass
class ToolDecision:
    """Decision from a single security tool"""
    tool_name: str
    decision: Decision
    confidence: float  # 0.0 to 1.0
    latency_ms: float
    reason: str
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class SecurityTool:
    """Base class for security tools"""
    
    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight  # Voting weight
        self.total_decisions = 0
        self.correct_decisions = 0
        self.avg_latency = 0.0
        
    async def evaluate(self, event: SecurityEvent) -> ToolDecision:
        """Evaluate security event - to be implemented by subclasses"""
        raise NotImplementedError
    
    def update_stats(self, latency: float, was_correct: bool):
        """Update tool statistics for adaptive weighting"""
        self.total_decisions += 1
        if was_correct:
            self.correct_decisions += 1
        
        # Exponential moving average for latency
        alpha = 0.1
        self.avg_latency = alpha * latency + (1 - alpha) * self.avg_latency
    
    @property
    def accuracy(self) -> float:
        """Historical accuracy"""
        return self.correct_decisions / max(self.total_decisions, 1)


class OPAGatekeeperTool(SecurityTool):
    """OPA Gatekeeper integration"""
    
    def __init__(self):
        super().__init__("OPA-Gatekeeper", weight=3.0)  # Highest weight for policy engine
        
    async def evaluate(self, event: SecurityEvent) -> ToolDecision:
        """Evaluate against OPA policies"""
        start_time = datetime.now()
        
        # Simulate OPA policy evaluation
        # In production, call OPA API: POST /v1/data/kubernetes/admission
        
        decision = Decision.ALLOW
        reason = "No policy violations"
        confidence = 0.95
        
        # Check for common violations
        if event.manifest:
            spec = event.manifest.get('spec', {})
            
            # Check privileged
            containers = spec.get('containers', [])
            for c in containers:
                if c.get('securityContext', {}).get('privileged'):
                    decision = Decision.BLOCK
                    reason = "Privileged container not allowed"
                    confidence = 1.0
                    break
            
            # Check host namespaces
            if spec.get('hostPID') or spec.get('hostNetwork'):
                decision = Decision.BLOCK
                reason = "Host namespace sharing not allowed"
                confidence = 1.0
        
        latency = (datetime.now() - start_time).total_seconds() * 1000
        
        return ToolDecision(
            tool_name=self.name,
            decision=decision,
            confidence=confidence,
            latency_ms=latency,
            reason=reason
        )


class FalcoTool(SecurityTool):
    """Falco runtime security integration"""
    
    def __init__(self):
        super().__init__("Falco", weight=1.0)
        
    async def evaluate(self, event: SecurityEvent) -> ToolDecision:
        """Evaluate runtime behavior against Falco rules"""
        start_time = datetime.now()
        
        # Simulate Falco rule evaluation
        # In production, query Falco gRPC API or parse audit logs
        
        decision = Decision.ALLOW
        reason = "No runtime violations detected"
        confidence = 0.85
        
        # Example runtime checks
        if event.metadata:
            if event.metadata.get('exec_command') in ['nc', 'curl', 'wget']:
                decision = Decision.ALERT
                reason = "Suspicious command execution detected"
                confidence = 0.75
        
        latency = (datetime.now() - start_time).total_seconds() * 1000
        
        return ToolDecision(
            tool_name=self.name,
            decision=decision,
            confidence=confidence,
            latency_ms=latency,
            reason=reason
        )


class AIAnomalyTool(SecurityTool):
    """AI-driven anomaly detection (IADRA integration)"""
    
    def __init__(self, model_path: Optional[str] = None):
        super().__init__("AI-Anomaly-Detector", weight=0.8)
        self.model_path = model_path
        # In production, load actual ML model here
        
    async def evaluate(self, event: SecurityEvent) -> ToolDecision:
        """Evaluate using AI/ML anomaly detection"""
        start_time = datetime.now()
        
        # Simulate ML inference
        # In production, call IADRA.detect_anomaly()
        
        decision = Decision.ALLOW
        reason = "Behavior within normal parameters"
        confidence = 0.70
        
        # Simple heuristic for demo
        if event.manifest:
            # Image tag analysis
            containers = event.manifest.get('spec', {}).get('containers', [])
            for c in containers:
                image = c.get('image', '')
                if 'latest' in image or ':dev' in image:
                    decision = Decision.ALERT
                    reason = "Unversioned image tag (supply chain risk)"
                    confidence = 0.65
        
        latency = (datetime.now() - start_time).total_seconds() * 1000
        
        return ToolDecision(
            tool_name=self.name,
            decision=decision,
            confidence=confidence,
            latency_ms=latency,
            reason=reason
        )


class EventRouter:
    """Intelligent event routing to appropriate tools"""
    
    @staticmethod
    def route_event(event: SecurityEvent, tools: List[SecurityTool]) -> List[SecurityTool]:
        """
        Determine which tools should evaluate this event.
        
        Optimization: Not all tools need to evaluate every event.
        """
        selected = []
        
        # OPA always evaluates admission events
        if event.event_type in ['pod_create', 'pod_update', 'deployment_create']:
            selected.extend([t for t in tools if 'OPA' in t.name])
        
        # Falco evaluates runtime events
        if event.event_type in ['exec', 'network_connect', 'file_access']:
            selected.extend([t for t in tools if 'Falco' in t.name])
        
        # AI evaluates everything for learning
        selected.extend([t for t in tools if 'AI' in t.name])
        
        # If routing is unclear, use all tools
        if not selected:
            selected = tools
        
        return selected


class DecisionFusion:
    """Fuses decisions from multiple tools using weighted voting"""
    
    @staticmethod
    def weighted_vote(decisions: List[ToolDecision]) -> ToolDecision:
        """
        Combine multiple tool decisions using weighted voting.
        
        Algorithm:
        1. Weight each decision by (tool_weight * confidence)
        2. Sum weights per decision type
        3. Choose decision with highest weighted score
        """
        if not decisions:
            return ToolDecision(
                tool_name="Fusion",
                decision=Decision.UNKNOWN,
                confidence=0.0,
                latency_ms=0.0,
                reason="No decisions to fuse"
            )
        
        # Aggregate weighted scores
        scores = {Decision.BLOCK: 0.0, Decision.ALERT: 0.0, Decision.ALLOW: 0.0}
        total_weight = 0.0
        total_latency = 0.0
        reasons = []
        
        for td in decisions:
            weight = td.confidence  # In production, multiply by tool.weight
            scores[td.decision] += weight
            total_weight += weight
            total_latency += td.latency_ms
            if td.decision != Decision.ALLOW:
                reasons.append(f"{td.tool_name}: {td.reason}")
        
        # Choose decision with highest score
        final_decision = max(scores, key=scores.get)
        final_confidence = scores[final_decision] / max(total_weight, 1.0)
        
        return ToolDecision(
            tool_name="Fusion-Engine",
            decision=final_decision,
            confidence=final_confidence,
            latency_ms=total_latency / len(decisions),
            reason=" | ".join(reasons) if reasons else "All tools agree: ALLOW",
            metadata={'individual_decisions': [d.__dict__ for d in decisions]}
        )


class ThresholdAdapter:
    """Dynamically adapt decision thresholds based on feedback"""
    
    def __init__(self):
        self.fp_count = 0  # False positives
        self.fn_count = 0  # False negatives
        self.tp_count = 0  # True positives
        self.block_threshold = 0.5  # Confidence threshold for blocking (lowered for strict mode)
        
    def adapt_threshold(self):
        """
        Adapt blocking threshold based on FP/FN rates.
        
        If FP rate is high: Increase threshold (be more conservative)
        If FN rate is high: Decrease threshold (be more aggressive)
        """
        total = self.fp_count + self.fn_count + self.tp_count
        if total < 100:  # Need sufficient data
            return
        
        fp_rate = self.fp_count / total
        fn_rate = self.fn_count / total
        
        if fp_rate > 0.05:  # Too many false positives
            self.block_threshold = min(0.95, self.block_threshold + 0.05)
            logger.info(f"↑ Increased block threshold to {self.block_threshold:.2f} (FP rate: {fp_rate:.2%})")
        elif fn_rate > 0.02:  # Too many false negatives
            self.block_threshold = max(0.5, self.block_threshold - 0.05)
            logger.info(f"↓ Decreased block threshold to {self.block_threshold:.2f} (FN rate: {fn_rate:.2%})")
    
    def update_feedback(self, was_fp: bool = False, was_fn: bool = False, was_tp: bool = False):
        """Update statistics based on feedback"""
        if was_fp:
            self.fp_count += 1
        if was_fn:
            self.fn_count += 1
        if was_tp:
            self.tp_count += 1
        
        self.adapt_threshold()


class SecurityOrchestrator:
    """Main ASOA engine - orchestrates all security tools"""
    
    def __init__(self, tools: Optional[List[SecurityTool]] = None):
        self.tools = tools or [
            OPAGatekeeperTool(),
            FalcoTool(),
            AIAnomalyTool()
        ]
        self.router = EventRouter()
        self.fusion = DecisionFusion()
        self.adapter = ThresholdAdapter()
        self.event_history = []
        
    async def evaluate_event(self, event: SecurityEvent) -> ToolDecision:
        """
        Evaluate a security event using orchestrated tools.
        
        Time Complexity: O(t log t) where t = number of tools
        """
        logger.info(f"Evaluating event: {event.event_id} ({event.event_type})")
        
        # Step 1: Route event to appropriate tools
        selected_tools = self.router.route_event(event, self.tools)
        logger.debug(f"Routed to {len(selected_tools)} tools: {[t.name for t in selected_tools]}")
        
        # Step 2: Parallel evaluation by all selected tools
        tasks = [tool.evaluate(event) for tool in selected_tools]
        tool_decisions = await asyncio.gather(*tasks)
        
        # Step 3: Fuse decisions
        final_decision = self.fusion.weighted_vote(tool_decisions)
        
        # Step 4: Apply adaptive threshold
        if final_decision.decision == Decision.BLOCK:
            if final_decision.confidence < self.adapter.block_threshold:
                # Downgrade to alert if confidence is below threshold
                final_decision.decision = Decision.ALERT
                final_decision.reason += f" (Confidence {final_decision.confidence:.2f} below threshold {self.adapter.block_threshold:.2f})"
        
        # Log decision
        logger.info(f"✅ Decision: {final_decision.decision.value} "
                   f"(confidence: {final_decision.confidence:.2f}, "
                   f"latency: {final_decision.latency_ms:.1f}ms)")
        
        self.event_history.append((event, final_decision))
        return final_decision
    
    def provide_feedback(self, event_id: str, was_correct: bool):
        """Provide feedback for adaptive learning"""
        # Update tools and adapter based on feedback
        if was_correct:
            self.adapter.update_feedback(was_tp=True)
        else:
            # Determine if it was FP or FN based on decision
            for event, decision in self.event_history:
                if event.event_id == event_id:
                    if decision.decision == Decision.BLOCK:
                        self.adapter.update_feedback(was_fp=True)
                    else:
                        self.adapter.update_feedback(was_fn=True)
                    break
    
    def get_statistics(self) -> Dict:
        """Get orchestrator statistics"""
        return {
            'total_events': len(self.event_history),
            'tools': [
                {
                    'name': t.name,
                    'weight': t.weight,
                    'accuracy': t.accuracy,
                    'avg_latency_ms': t.avg_latency
                }
                for t in self.tools
            ],
            'block_threshold': self.adapter.block_threshold,
            'fp_count': self.adapter.fp_count,
            'fn_count': self.adapter.fn_count
        }


# Example usage
async def main():
    # Create orchestrator
    orchestrator = SecurityOrchestrator()
    
    # Example event
    event = SecurityEvent(
        event_id="evt-001",
        event_type="pod_create",
        timestamp=datetime.now(),
        resource_kind="Pod",
        resource_name="test-pod",
        manifest={
            'apiVersion': 'v1',
            'kind': 'Pod',
            'spec': {
                'hostPID': True,
                'containers': [{
                    'name': 'app',
                    'image': 'nginx:latest',
                    'securityContext': {'privileged': True}
                }]
            }
        }
    )
    
    # Evaluate
    decision = await orchestrator.evaluate_event(event)
    
    print(f"\n✅ ASOA Evaluation Complete!")
    print(f"   Decision: {decision.decision.value}")
    print(f"   Confidence: {decision.confidence:.2%}")
    print(f"   Latency: {decision.latency_ms:.1f}ms")
    print(f"   Reason: {decision.reason}")
    
    # Statistics
    stats = orchestrator.get_statistics()
    print(f"\n📊 Orchestrator Statistics:")
    print(f"   Total events: {stats['total_events']}")
    print(f"   Block threshold: {stats['block_threshold']:.2f}")


if __name__ == "__main__":
    asyncio.run(main())
