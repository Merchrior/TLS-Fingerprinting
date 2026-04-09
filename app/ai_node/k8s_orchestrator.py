import logging
from kubernetes import client, config
from app.core.config_loader import Config

class AIOrchestrator:
    """Manages scaling and execution of AI discovery containers via Kubernetes."""
    
    def __init__(self):
        self.namespace = Config().data['ai_kubernetes']['namespace']
        try:
            config.load_kube_config()
            self.batch_v1 = client.BatchV1Api()
        except Exception as e:
            logging.warning(f"K8s not configured locally. Running in Simulation Mode. Error: {e}")
            self.batch_v1 = None

    def trigger_discovery_job(self, ja3_string: str) -> dict:
        """Submits a job to K8s for Pattern Mining."""
        if not self.batch_v1:
            # Simulation response if K8s is not running locally
            logging.info("Simulating AI Discovery logic...")
            return {"label": "AI_Predicted_Malware_Family_X", "confidence": 0.95}

        job_name = f"ai-discovery-{abs(hash(ja3_string))}"
        job_manifest = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": job_name, "namespace": self.namespace},
            "spec": {
                "ttlSecondsAfterFinished": Config().data['ai_kubernetes']['scale_to_zero_minutes'] * 60,
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "miner",
                            "image": "tls-ai-miner:latest",
                            "env": [{"name": "JA3_TARGET", "value": ja3_string}],
                        }],
                        "restartPolicy": "Never"
                    }
                }
            }
        }
        
        try:
            self.batch_v1.create_namespaced_job(body=job_manifest, namespace=self.namespace)
            logging.info(f"Triggered K8s AI Job: {job_name}")
            return {"label": "Pending_K8s_Analysis", "confidence": 0.0}
        except Exception as e:
            logging.error(f"Failed to trigger K8s Job: {e}")
            return {"label": "Error", "confidence": 0.0}