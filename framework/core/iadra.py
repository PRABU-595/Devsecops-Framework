"""
IADRA: Intelligent Anomaly Detection & Response Algorithm
==========================================================

AI-driven ensemble anomaly detection with automated response.

Algorithm Complexity:
- Training: O(n log n)
- Inference: O(log n)
Space Complexity: O(n · f) where f = features

Author: Prabu, Divya, Vijayalakshmi
Paper: "A Unified DevSecOps Framework for Policy-Driven and AI-Augmented Cloud-Native Security"
"""

import logging
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum
import pickle

# ML imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of anomalies"""
    PRIVILEGE_ESC = "privilege_escalation"
    CONTAINER_ESCAPE = "container_escape"
    RESOURCE_ABUSE = "resource_abuse"
    NETWORK_ANOMALY = "network_anomaly"
    SUPPLY_CHAIN = "supply_chain"
    BEHAVIORAL = "behavioral"
    NORMAL = "normal"


@dataclass
class AnomalyResult:
    """Result from anomaly detection"""
    is_anomaly: bool
    anomaly_type: AnomalyType
    confidence: float
    anomaly_score: float
    feature_contributions: Dict[str, float]
    recommended_action: str


class FeatureExtractor:
    """
    Extract 15-dimensional feature vector from Kubernetes events.
    
    Features:
    1. privilege_level (binary)
    2. capability_count
    3. host_pid (binary)
    4. host_network (binary)
    5. host_ipc (binary)
    6. resource_limit_ratio
    7. image_entropy (supply chain risk)
    8. network_exposure_score
    9. volume_mount_risk
    10. user_id_risk
    11. seccomp_profile (binary)
    12. apparmor_profile (binary)
    13. readonly_rootfs (binary)
    14. drop_all_capabilities (binary)
    15. run_as_nonroot (binary)
    """
    
    @staticmethod
    def extract(manifest: Dict) -> np.ndarray:
        """Extract feature vector from Kubernetes manifest"""
        features = np.zeros(15)
        
        if not manifest:
            return features
        
        spec = manifest.get('spec', {})
        containers = spec.get('containers', []) + spec.get('initContainers', [])
        
        if not containers:
            return features
        
        container = containers[0]  # Focus on first container
        sec_ctx = container.get('securityContext', {})
        
        # Feature 1: Privilege level
        features[0] = 1.0 if sec_ctx.get('privileged') else 0.0
        
        # Feature 2: Capability count
        caps = sec_ctx.get('capabilities', {}).get('add', [])
        features[1] = len(caps)
        
        # Features 3-5: Host namespace sharing
        features[2] = 1.0 if spec.get('hostPID') else 0.0
        features[3] = 1.0 if spec.get('hostNetwork') else 0.0
        features[4] = 1.0 if spec.get('hostIPC') else 0.0
        
        # Feature 6: Resource limit ratio
        resources = container.get('resources', {})
        limits = resources.get('limits', {})
        requests = resources.get('requests', {})
        
        cpu_limit = FeatureExtractor._parse_cpu(limits.get('cpu', '0'))
        cpu_request = FeatureExtractor._parse_cpu(requests.get('cpu', '0'))
        
        features[5] = cpu_limit / max(cpu_request, 0.001) if cpu_request else 10.0
        
        # Feature 7: Image entropy (supply chain risk)
        image = container.get('image', '')
        features[6] = FeatureExtractor._compute_image_risk(image)
        
        # Feature 8: Network exposure score
        ports = container.get('ports', [])
        features[7] = len(ports)  # Simplified
        
        # Feature 9: Volume mount risk
        volume_mounts = container.get('volumeMounts', [])
        volumes = spec.get('volumes', [])
        host_path_count = sum(1 for v in volumes if 'hostPath' in v)
        features[8] = host_path_count
        
        # Feature 10: User ID risk (0 = root = high risk)
        run_as_user = sec_ctx.get('runAsUser', 0)
        features[9] = 1.0 if run_as_user == 0 else 0.0
        
        # Feature 11: Seccomp profile
        features[10] = 0.0 if sec_ctx.get('seccompProfile') else 1.0
        
        # Feature 12: AppArmor profile
        annotations = manifest.get('metadata', {}).get('annotations', {})
        features[11] = 0.0 if any('apparmor' in k.lower() for k in annotations.keys()) else 1.0
        
        # Feature 13: Readonly root filesystem
        features[12] = 0.0 if sec_ctx.get('readOnlyRootFilesystem') else 1.0
        
        # Feature 14: Drop all capabilities
        drop_caps = sec_ctx.get('capabilities', {}).get('drop', [])
        features[13] = 1.0 if 'ALL' in drop_caps else 0.0
        
        # Feature 15: Run as non-root
        features[14] = 1.0 if sec_ctx.get('runAsNonRoot') else 0.0
        
        return features
    
    @staticmethod
    def _parse_cpu(cpu_str: str) -> float:
        """Parse CPU string (e.g., '100m' -> 0.1)"""
        if not cpu_str:
            return 0.0
        if cpu_str.endswith('m'):
            return float(cpu_str[:-1]) / 1000
        return float(cpu_str)
    
    @staticmethod
    def _compute_image_risk(image: str) -> float:
        """Compute image supply chain risk score"""
        risk = 0.0
        
        # High risk: latest tag
        if ':latest' in image or not ':' in image:
            risk += 3.0
        
        # Medium risk: dev/debug tags
        if any(tag in image.lower() for tag in [':dev', ':debug', ':test']):
            risk += 2.0
        
        # Low risk: trusted registries
        trusted = ['gcr.io', 'docker.io/library', 'quay.io']
        if any(reg in image for reg in trusted):
            risk -= 1.0
        
        return max(0.0, risk)


class AnomalyDetector:
    """
    Ensemble anomaly detection using:
    1. Isolation Forest (unsupervised)
    2. Random Forest (supervised)
    3. Multi-Layer Perceptron (deep learning)
    """
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.mlp = MLPClassifier(
            hidden_layer_sizes=(64, 32, 16),
            activation='relu',
            max_iter=500,
            random_state=42
        )
        self.is_trained = False
        self.feature_extractor = FeatureExtractor()
        
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None):
        """
        Train ensemble models.
        
        Args:
            X: Feature matrix (n_samples, 15)
            y: Labels (optional, for supervised models)
            
        Time Complexity: O(n log n)
        """
        logger.info(f"Training IADRA on {len(X)} samples...")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest (unsupervised)
        self.isolation_forest.fit(X_scaled)
        logger.info("✅ Isolation Forest trained")
        
        # Train supervised models if labels provided
        if y is not None:
            self.random_forest.fit(X_scaled, y)
            logger.info("✅ Random Forest trained")
            
            self.mlp.fit(X_scaled, y)
            logger.info("✅ MLP trained")
        
        self.is_trained = True
        logger.info("✅ IADRA training complete")
    
    def detect_anomaly(self, manifest: Dict) -> AnomalyResult:
        """
        Detect anomaly in Kubernetes manifest.
        
        Time Complexity: O(log n) for inference
        """
        if not self.is_trained:
            logger.warning("Model not trained, using heuristics only")
            return self._heuristic_detection(manifest)
        
        # Extract features
        features = self.feature_extractor.extract(manifest)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Get ensemble predictions
        if_score = self.isolation_forest.score_samples(features_scaled)[0]
        if_pred = self.isolation_forest.predict(features_scaled)[0]  # -1 = anomaly, 1 = normal
        
        rf_proba = self.random_forest.predict_proba(features_scaled)[0]
        mlp_proba = self.mlp.predict_proba(features_scaled)[0]
        
        # Weighted ensemble (40% IF, 30% RF, 30% MLP)
        # IF score is negative for anomalies, normalize to 0-1
        if_anomaly_score = 1.0 / (1.0 + np.exp(if_score))  # Sigmoid
        rf_anomaly_score = rf_proba[1] if len(rf_proba) > 1 else 0.5
        mlp_anomaly_score = mlp_proba[1] if len(mlp_proba) > 1 else 0.5
        
        ensemble_score = (
            0.4 * if_anomaly_score +
            0.3 * rf_anomaly_score +
            0.3 * mlp_anomaly_score
        )
        
        is_anomaly = ensemble_score > 0.5
        confidence = ensemble_score if is_anomaly else (1.0 - ensemble_score)
        
        # Determine anomaly type from features
        anomaly_type = self._classify_anomaly_type(features)
        
        # Feature contributions
        feature_names = [
            'privilege', 'capabilities', 'hostPID', 'hostNetwork', 'hostIPC',
            'resource_ratio', 'image_risk', 'network_exposure', 'volume_risk',
            'root_user', 'no_seccomp', 'no_apparmor', 'writable_rootfs',
            'keeps_caps', 'run_as_root'
        ]
        contributions = dict(zip(feature_names, features))
        
        # Recommended action
        action = self._recommend_action(is_anomaly, anomaly_type, ensemble_score)
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
            confidence=confidence,
            anomaly_score=ensemble_score,
            feature_contributions=contributions,
            recommended_action=action
        )
    
    def _heuristic_detection(self, manifest: Dict) -> AnomalyResult:
        """Fallback heuristic-based detection when model not trained"""
        features = self.feature_extractor.extract(manifest)
        
        # Simple threshold-based detection (more aggressive)
        risk_score = (
            features[0] * 10 +  # Privileged (increased)
            features[2] * 8 +   # hostPID (increased)
            features[3] * 8 +   # hostNetwork (increased)
            features[6] * 3 +   # Image risk (increased)
            features[9] * 6     # Root user (increased)
        )
        
        is_anomaly = risk_score > 3.0  # Lowered threshold
        anomaly_type = self._classify_anomaly_type(features)
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
            confidence=min(risk_score / 10.0, 1.0),
            anomaly_score=risk_score,
            feature_contributions={},
            recommended_action="ALERT" if is_anomaly else "ALLOW"
        )
    
    @staticmethod
    def _classify_anomaly_type(features: np.ndarray) -> AnomalyType:
        """Classify anomaly type based on dominant features"""
        if features[0] > 0 or features[1] > 2:  # Privileged or many capabilities
            return AnomalyType.PRIVILEGE_ESC
        if features[2] > 0 or features[3] > 0 or features[4] > 0:  # Host namespaces
            return AnomalyType.CONTAINER_ESCAPE
        if features[5] > 5.0:  # High resource ratio
            return AnomalyType.RESOURCE_ABUSE
        if features[6] > 2.0:  # High image risk
            return AnomalyType.SUPPLY_CHAIN
        if features[7] > 5:  # Many network ports
            return AnomalyType.NETWORK_ANOMALY
        
        return AnomalyType.NORMAL
    
    @staticmethod
    def _recommend_action(is_anomaly: bool, anomaly_type: AnomalyType, score: float) -> str:
        """Recommend action based on detection result"""
        if not is_anomaly:
            return "ALLOW"
        
        # Critical anomalies -> BLOCK
        if anomaly_type in [AnomalyType.PRIVILEGE_ESC, AnomalyType.CONTAINER_ESCAPE]:
            return "BLOCK"
        
        # High confidence -> BLOCK, low confidence -> ALERT
        if score > 0.8:
            return "BLOCK"
        elif score > 0.6:
            return "ALERT"
        else:
            return "MONITOR"
    
    def save_model(self, filepath: str):
        """Save trained model to disk"""
        model_data = {
            'scaler': self.scaler,
            'isolation_forest': self.isolation_forest,
            'random_forest': self.random_forest,
            'mlp': self.mlp,
            'is_trained': self.is_trained
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"✅ Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model from disk"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.scaler = model_data['scaler']
        self.isolation_forest = model_data['isolation_forest']
        self.random_forest = model_data['random_forest']
        self.mlp = model_data['mlp']
        self.is_trained = model_data['is_trained']
        
        logger.info(f"✅ Model loaded from {filepath}")


# Example usage
if __name__ == "__main__":
    # Initialize detector
    detector = AnomalyDetector()
    
    # Generate synthetic training data (in production, use real attack/benign data)
    np.random.seed(42)
    X_benign = np.random.randn(100, 15) * 0.3  # Benign workloads
    X_malicious = np.random.randn(20, 15) * 2.0 + 3.0  # Malicious workloads
    
    X = np.vstack([X_benign, X_malicious])
    y = np.array([0] * 100 + [1] * 20)  # 0 = benign, 1 = malicious
    
    # Train
    detector.train(X, y)
    
    # Test on malicious manifest
    test_manifest = {
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
                    'runAsUser': 0
                }
            }]
        }
    }
    
    result = detector.detect_anomaly(test_manifest)
    
    print(f"\n✅ IADRA Detection Complete!")
    print(f"   Is Anomaly: {result.is_anomaly}")
    print(f"   Type: {result.anomaly_type.value}")
    print(f"   Confidence: {result.confidence:.2%}")
    print(f"   Score: {result.anomaly_score:.3f}")
    print(f"   Action: {result.recommended_action}")
    
    # Save model
    detector.save_model('iadra_model.pkl')
