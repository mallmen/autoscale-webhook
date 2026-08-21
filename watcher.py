import os
import time
import logging
from kubernetes import client, config, watch

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Load cluster config
try:
    config.load_incluster_config()
except Exception:
    config.load_kube_config()

v1 = client.CoreV1Api()
batch_v1 = client.BatchV1Api()

# Environment settings
WATCHER_NAMESPACE = os.getenv("WATCHER_NAMESPACE", "autoscale-node-automation")
AAP_HOST = os.getenv("AAP_HOST", "aap.ipa.mikea.net")
WORKFLOW_ID = os.getenv("WORKFLOW_ID", "38")
TAINT_KEY = "network.zero-trust.io/firewall-unverified"

processed_nodes = set()

def is_node_ready(node):
    """Check if Node condition status is Ready == True."""
    for condition in node.status.conditions or []:
        if condition.type == "Ready" and condition.status == "True":
            return True
    return False

def has_quarantine_taint(node):
    """Check if node contains the quarantine taint."""
    for taint in node.spec.taints or []:
        if taint.key == TAINT_KEY:
            return True
    return False

def get_node_ip(node):
    """Extract InternalIP address from Node status."""
    for addr in node.status.addresses or []:
        if addr.type == "InternalIP":
            return addr.address
    return None

def trigger_onboarding_job(node_name, node_ip):
    """Spawn a Kubernetes Job that mounts token from aap-secret and triggers AAP."""
    job_manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": f"aap-onboard-{node_name}",
            "namespace": WATCHER_NAMESPACE,
            "labels": {"app": "aap-node-onboarding"}
        },
        "spec": {
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 300,
            "template": {
                "metadata": {
                    "labels": {"app": "aap-node-onboarding"}
                },
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [{
                        "name": "aap-trigger",
                        "image": "registry.access.redhat.com/ubi9/ubi-minimal:latest",
                        "command": ["/bin/sh", "-c"],
                        "env": [
                            {"name": "AAP_HOST", "value": AAP_HOST},
                            {"name": "WORKFLOW_ID", "value": WORKFLOW_ID},
                            {"name": "TARGET_NODE", "value": node_name},
                            {"name": "TARGET_IP", "value": node_ip},
                            {
                                "name": "AAP_TOKEN",
                                "valueFrom": {
                                    "secretKeyRef": {
                                        "name": "aap-secret",
                                        "key": "token"
                                    }
                                }
                            }
                        ],
                        "args": [
                            r"""
                            echo "========================================="
                            echo "Starting Onboarding Job for Node: ${TARGET_NODE} (IP: ${TARGET_IP})"
                            echo "========================================="

                            echo "[+] Calling AAP Workflow Template..."

                            HTTP_CODE=$(curl -k -s -o /tmp/response.json -w "%{http_code}" --connect-timeout 10 --max-time 30 -X POST \
                              "https://${AAP_HOST}/api/controller/v2/workflow_job_templates/${WORKFLOW_ID}/launch/" \
                              -H "Authorization: Bearer ${AAP_TOKEN}" \
                              -H "Content-Type: application/json" \
                              -d "{\"extra_vars\": {\"target_node_name\": \"${TARGET_NODE}\", \"target_node_ip\": \"${TARGET_IP}\"}}")

                            echo "AAP Response Code: ${HTTP_CODE}"
                            echo "AAP Response Body:"
                            cat /tmp/response.json
                            echo ""

                            if [ "${HTTP_CODE}" -eq 201 ] || [ "${HTTP_CODE}" -eq 200 ]; then
                                echo "[SUCCESS] AAP Workflow launched successfully."
                                exit 0
                            else
                                echo "[ERROR] AAP Workflow launch failed with HTTP status: ${HTTP_CODE}"
                                exit 1
                            fi
                            """
                        ]
                    }]
                }
            }
        }
    }

    try:
        batch_v1.create_namespaced_job(namespace=WATCHER_NAMESPACE, body=job_manifest)
        logging.info(f"Created Job aap-onboard-{node_name} in namespace {WATCHER_NAMESPACE}")
        processed_nodes.add(node_name)
    except client.exceptions.ApiException as e:
        logging.error(f"Failed to create Job for node {node_name}: {e}")

def main():
    logging.info(f"Starting Node Readiness Watcher in namespace: {WATCHER_NAMESPACE}...")
    w = watch.Watch()

    while True:
        try:
            for event in w.stream(v1.list_node):
                node = event['object']
                node_name = node.metadata.name

                if node_name in processed_nodes:
                    continue

                if is_node_ready(node) and has_quarantine_taint(node):
                    node_ip = get_node_ip(node)
                    if node_ip:
                        logging.info(f"Target node READY and TAINTED: {node_name} ({node_ip}). Launching Job...")
                        trigger_onboarding_job(node_name, node_ip)
                    else:
                        logging.warning(f"Node {node_name} is Ready and Tainted, but InternalIP is missing.")

        except Exception as e:
            logging.error(f"Watcher stream interrupted: {e}. Reconnecting in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    main()
