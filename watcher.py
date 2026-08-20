import os
import time
import logging
from kubernetes import client, config, watch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TARGET_TAINT_KEY = "network.zero-trust.io/firewall-unverified"
TARGET_TAINT_VAL = "true"
JOB_NAMESPACE = os.getenv("WATCHER_NAMESPACE", "openshift-machine-api")

# In-memory tracking to avoid spawning duplicate Jobs for the same node
processed_nodes = set()

def is_node_ready(node):
    """Check if Node condition Ready is True."""
    for cond in node.status.conditions or []:
        if cond.type == "Ready" and cond.status == "True":
            return True
    return False

def has_quarantine_taint(node):
    """Check if Node has the zero-trust webhook taint."""
    for taint in node.spec.taints or []:
        if taint.key == TARGET_TAINT_KEY and taint.value == TARGET_TAINT_VAL:
            return True
    return False

def get_node_ip(node):
    """Extract InternalIP from Node status."""
    for addr in node.status.addresses or []:
        if addr.type == "InternalIP":
            return addr.address
    return "Unknown"

def trigger_onboarding_job(batch_v1, node_name, node_ip):
    """Spawn a dedicated Kubernetes Job to perform AAP onboarding and untaint the node."""
    job_name = f"aap-onboard-{node_name}"
    
    # Sanitize job name for k8s naming rules
    job_name = job_name.lower().replace(".", "-")

    job_manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": JOB_NAMESPACE,
            "labels": {
                "app": "aap-node-onboarding",
                "target-node": node_name
            }
        },
        "spec": {
            "ttlSecondsAfterFinished": 300,  # Automatically clean up Job 5 mins after completion
            "backoffLimit": 3,
            "template": {
                "metadata": {
                    "labels": {
                        "app": "aap-node-onboarding"
                    }
                },
                "spec": {
                    "serviceAccountName": "aap-onboarding-job-sa",
                    "restartPolicy": "OnFailure",
                    "containers": [{
                        "name": "onboard-and-untaint",
                        "image": "registry.access.redhat.com/ubi9/ubi-minimal:latest",
                        "command": ["/bin/sh", "-c"],
                        "args": [
                            f"""
                            echo "========================================="
                            echo "Starting Onboarding Job for Node: {node_name} (IP: {node_ip})"
                            echo "========================================="

                            # 1. Trigger AAP REST API
                            echo "[+] Calling AAP Workflow Template..."
                            RESPONSE=$(curl -sk -X POST "https://${{AAP_HOST}}/api/v2/workflow_job_templates/${{WORKFLOW_ID}}/launch/" \
                              -H "Authorization: Bearer ${{AAP_TOKEN}}" \
                              -H "Content-Type: application/json" \
                              -d "{{\"extra_vars\": {{\"target_node_name\": \"{node_name}\", \"target_node_ip\": \"{node_ip}\"}}}}")

                            echo "AAP Launch Response: $RESPONSE"

                            # 2. Clear Quarantine Taint from Machine & Node
                            echo "[+] Removing quarantine taint from Machine and Node..."
                            TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
                            
                            # Patch Node
                            curl -sk -X PATCH \
                              -H "Authorization: Bearer $TOKEN" \
                              -H "Content-Type: application/json-patch+json" \
                              "https://kubernetes.default.svc/api/v1/nodes/{node_name}" \
                              -d '[{{"op": "replace", "path": "/spec/taints", "value": []}}]'

                            # Patch Machine
                            curl -sk -X PATCH \
                              -H "Authorization: Bearer $TOKEN" \
                              -H "Content-Type: application/json-patch+json" \
                              "https://kubernetes.default.svc/apis/machine.openshift.io/v1beta1/namespaces/openshift-machine-api/machines/{node_name}" \
                              -d '[{{"op": "replace", "path": "/spec/taints", "value": []}}]'

                            echo "[SUCCESS] Node {node_name} onboarded and untainted successfully."
                            """
                        ],
                        "env": [
                            {"name": "AAP_HOST", "value": os.getenv("AAP_HOST", "aap.example.com")},
                            {"name": "WORKFLOW_ID", "value": os.getenv("WORKFLOW_ID", "42")},
                            {
                                "name": "AAP_TOKEN",
                                "valueFrom": {
                                    "secretKeyRef": {
                                        "name": "aap-secret",
                                        "key": "token"
                                    }
                                }
                            }
                        ]
                    }]
                }
            }
        }
    }

    try:
        batch_v1.create_namespaced_job(namespace=JOB_NAMESPACE, body=job_manifest)
        logging.info(f"Successfully spawned Job '{job_name}' for node {node_name}")
        return True
    except Exception as e:
        logging.error(f"Failed to create Job for node {node_name}: {e}")
        return False

def main():
    logging.info("Starting Node Readiness Watcher...")
    
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()

    v1 = client.CoreV1Api()
    batch_v1 = client.BatchV1Api()
    w = watch.Watch()

    while True:
        try:
            for event in w.stream(v1.list_node, timeout_seconds=300):
                node = event['object']
                node_name = node.metadata.name

                if is_node_ready(node) and has_quarantine_taint(node):
                    if node_name not in processed_nodes:
                        node_ip = get_node_ip(node)
                        logging.info(f"Target node READY and TAINTED: {node_name} ({node_ip}). Launching Job...")
                        
                        if trigger_onboarding_job(batch_v1, node_name, node_ip):
                            processed_nodes.add(node_name)
                else:
                    # Clear memory cache if node was untainted
                    if node_name in processed_nodes and not has_quarantine_taint(node):
                        processed_nodes.remove(node_name)

        except Exception as e:
            logging.warning(f"Watch stream exception: {e}. Re-establishing stream in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    main()
