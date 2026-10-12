# OpenShift Machine API Mutating Admission Webhook  
  
![OpenShift](https://img.shields.io/badge/OpenShift-4.x-red?logo=redhatopenshift)  
![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)  
![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.28-326CE5?logo=kubernetes)  
  
A custom Mutating Admission Webhook designed for self-managed OpenShift Container Platform (OCP) environments to implement zero-trust network quarantine during automated node provisioning.  
  
When the OpenShift Cluster Autoscaler scales worker nodes, newly provisioned nodes must not accept user workloads until external network firewall rules are updated and verified. This webhook intercepts `Machine` resource creation events and automatically injects a custom `NoSchedule` quarantine taint into the machine specification.  
  
---  
  
## Table of Contents

- [Overview](#overview)
- [Architecture & Workflow](#architecture--workflow)
  - [3-Step Zero-Trust Lifecycle](#3-step-zero-trust-lifecycle)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Step 1: Webhook Implementation & Build](#step-1-webhook-implementation--build)
  - [1. Initialize Go Module & Dependencies (`go.mod` & `go.sum`)](#1-initialize-go-module--dependencies-gomod--gosum)
  - [2. Go Source Code (`main.go`)](#2-go-source-code-maingo)
  - [3. Multi-Stage Container Build (`Dockerfile`)](#3-multi-stage-container-build-dockerfile)
  - [4. Build and Push Container Image](#4-build-and-push-container-image)
- [Step 2: Deployment & Configuration](#step-2-deployment--configuration)
  - [Manifest Breakdown & Architectural Requirements](#manifest-breakdown--architectural-requirements)
  - [1. Cluster Pull Credentials](#1-cluster-pull-credentials)
  - [2. Application Manifests (`webhook-deployment.yml`)](#2-application-manifests-webhook-deploymentyml)
  - [3. Mutating Webhook Registration (`webhook-config.yml`)](#3-mutating-webhook-registration-webhook-configyml)
  - [4. Watcher Application Manifests (`watcher-and-job-rbac.yml`)](#4--watcher-application-manifests-watcher-and-job-rbacyml)
  - [5. Watcher Python Script (`watcher.py`)](#5--watcher-python-script-watcherpy)
  - [Apply Manifests](#apply-manifests)
- [Verification & Testing](#verification--testing)
  - [1. Tail Webhook Application Logs](#1-tail-webhook-application-logs)
  - [2. Scale Up Worker MachineSet](#2-scale-up-worker-machineset)
  - [3. Verify Taint Injection on Machine Object](#3-verify-taint-injection-on-machine-object)
  - [4. Verify AAP Workflow Execution and Removal of Taint from Node and Machine](#4-verify-aap-workflow-execution-and-removal-of-taint-from-node-and-machine)
- [Troubleshooting Matrix](#troubleshooting-matrix)
  
---  
  
## Overview  
  
In zero-trust environments, worker nodes booted by the Cluster Autoscaler cannot route traffic cleanly until physical or software firewall controllers process the new node IP address. By modifying the `worker` MachineSet, all newly created nodes come online with a `NoSchedule` taint. After the node is created and ready, a watcher pod will detect the newly created node and execute a job that uses the AAP API to call a workflow job template that untaints the node for operation.  This workflow can be customized to perform additional work prior to removing the taint.  For example, the firewall for the zero-trust environment can be updated for the newly created node, and the firewall can be validated prior to removing the taint.
  
---  
  
## Architecture & Workflow  
  
```text  
+-----------------------+ 1. CREATE new node with NoSchedule Taint
| Cluster Autoscaler    | 
| (Machine API)         | 
+-----------------------+ 
           |  
           v 2. Commit Spec  
 +-----------------------------+  
 | Machine Resource Created    |  
 | (Quarantined by Taint)      |  
 +-----------------------------+  
           |  
           v 3. Provision VM  
+-----------------------+ 4. Extract IP & Update +-----------------------------+  
| Automation Controller | <--------------------- | Node Boots / Enters Running |  
| (Ansible / Operator)  |                        +-----------------------------+  
+-----------------------+                                       |  
           | 5. Apply Firewall Rules                            v  
           v                                     +-----------------------------+  
+-----------------------+                        | Verification DaemonSet      |  
| External Firewall API |                        | (Runs network probes)       |  
+-----------------------+                        +-----------------------------+  
                                                                | 6. Remove Taint  
                                                                v  
                                                 +-----------------------------+  
                                                 | Node Fully Unlocked         |  
                                                 | (Schedules User Workloads)  |  
                                                 +-----------------------------+  

```

### 3-Step Zero-Trust Lifecycle

1. **Node Creation & Quarantine:** The worker MachineSet creates new Machine resources to apply `network.zero-trust.io/firewall-unverified=true:NoSchedule`.
2. **Node Discovery:** A watcher pod detects the newly configured and ready node and executes an OpenShift job to call a workflow job template using the AAP API.
3. **Firewall Automation, Validation, and Release:** The AAP workflow updates the firewall rules, validates the rules are working, and releases the node by removing the taint.

## Key Features

- **Dynamic JSON Patching:** Mutates incoming Machine objects to append the zero-trust quarantine taint without overwriting existing taints.
- **Automated TLS Integration:** Leverages OpenShift's native service-ca operator to handle certificate generation, signing, and CA bundle injection.
- **Strict Security Compliance:** Configured with explicit NetworkPolicy ingress rules to function inside OpenShift's default-deny `openshift-machine-api` namespace.
- **Defensive Runtime:** Guarded against nil-pointer panics caused by health probes or malformed API requests.

## Project Structure

```plaintext
autoscale-webhook/  
├── Containerfile                    # ~~Containerfile to build Go HTTP server container~~ Ignore
├── main.go                          # ~~Go HTTP server handling AdmissionReview logic~~ Ignore
├── go.mod                           # ~~Go module definition (v1.22+)~~ Ignore  
├── go.sum                           # ~~dependency lockfile~~ Ignore
├── manifests                        # 
│    └── watcher-and-job-rbac.yml    # OpenShift namespace, serviceaccounts, rbac, and deployment  
│    └── webhook-deployment.yml      # ~~OpenShift deployment, service, and networkPolicy~~ Ignore  
│    └── webhook-config.yml.yml      # ~~OpenShift mutatingwebhookconfiguration manifest~~ Ignore
├── playbooks                        # 
│    └── remove-autoscale-taint.yml  # Ansible playbook to remove machine and node taint
└── README.md                        # project documentation
```

## Prerequisites

- OpenShift Cluster (v4.x) with `cluster-admin` access.
- OpenShift CLI (`oc`) installed.
- Container engine (`podman` or `docker`).
- Access to an enterprise container registry (e.g., Quay.io).

## Step 1: MachineSet modification

Apply a custom Taint to the worker `MachineSet`.
```bash
$ oc project openshift-machine-api

$ oc get machinesets.machines
NAME                  DESIRED   CURRENT   READY   AVAILABLE   AGE
ocp4-crg55-worker-0   0         0                             39d
ocp4-crg55-worker-1   3         3         3       3           31d

$ oc edit machinesets.machines ocp4-crg55-worker-1
```
Add the taint to `spec.template.spec`.

```yaml
taints:
    - key: network.zero-trust.io/firewall-unverified
      value: "true"
      effect: NoSchedule
```
> [!WARNING]
> Make sure this taint is unique and is not used for node troubleshooting.  If this value is not unique, this may disrupt normal cluster operations.
---

### 2.  Watcher Application Manifests (`watcher-and-job-rbac.yml`)

This bundle provisions a namespace, service accounts, role bindings, and the deployment for the Watcher application that calls the AAP workflow after a new node is provisioned.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: autoscale-node-automation
  labels:
    openshift.io/cluster-monitoring: "true"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: node-readiness-watcher-sa
  namespace: autoscale-node-automation
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-readiness-watcher-role
rules:
  # Permission to watch Node state cluster-wide
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  # Permission to create and manage onboarding Jobs in autoscale-node-automation
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["get", "list", "create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: node-readiness-watcher-binding
subjects:
  - kind: ServiceAccount
    name: node-readiness-watcher-sa
    namespace: autoscale-node-automation
roleRef:
  kind: ClusterRole
  name: node-readiness-watcher-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: node-readiness-watcher
  namespace: autoscale-node-automation
  labels:
    app: node-readiness-watcher
spec:
  replicas: 1
  selector:
    matchLabels:
      app: node-readiness-watcher
  template:
    metadata:
      labels:
        app: node-readiness-watcher
    spec:
      serviceAccountName: node-readiness-watcher-sa
      containers:
        - name: watcher
          image: registry.access.redhat.com/ubi9/python-312:latest
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-c"]
          args:
            - |
              pip install --quiet kubernetes
              python -u /app/watcher.py
          env:
            - name: WATCHER_NAMESPACE
              value: "autoscale-node-automation"
            - name: AAP_HOST
              value: "aap.ipa.mikea.net"
            - name: WORKFLOW_ID
              value: "38"
            - name: AAP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: aap-secret
                  key: token
          volumeMounts:
            - name: script
              mountPath: /app
      volumes:
        - name: script
          configMap:
            name: node-readiness-watcher-script
```
> [!TIP]
> In the `node-readiness-watcher` Deployment, change `image` to the desired image location.  The example uses a free Red Hat Python image.  To use an image from a local registry, update this line.

#### Why These Resources Are Configured This Way:

* **Why Provision a New Namespace:**  
  The Watcher application is user workload despite operating on system resources.  It is best practice to maintain this application in its own namespace.

* **Why Use ServiceAccounts and Cluster Roles (`node-readiness-watcher-role`):**  
  The Watcher application must be able to stream Node events and spawn onboarding Jobs.
---

### 5.  Watcher Python Script (`watcher.py`)

```python
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
```
> [!TIP]
> In the `trigger_onboarding_job` function, when defining `spec.template.spec.containers` for the `job_manifest`, name the container something appropriate for the function.  Update the image as needed to use a local image if necessary.  The Red Hat `ubi9/ubi-minimal:latest` image is used for the small footprint and because it provides `curl` which is used for the API call.

#### Why `watcher.py` is Managed as a Standalone File:

Managing the `watcher.py` Python script as a separate file allows it to be maintained without requring a custom container image rebuild.  It can be mounted into the Deployment allowing for changes to be made with a simple restart of the Deployment.

---

### Apply Manifests

Create the watcher namespace:

```bash
oc apply -f namespace.yml
```

Apply the watcher deployment, service account, and rbac manifests:

```bash
oc apply -f watcher-and-job-rbac.yml
```

Create the Watcher configmap:

```bash
oc create configmap node-readiness-watcher-script \
  --from-file=watcher.py=watcher.py -n autoscale-node-automation
```

Restart the deployment to mount the watcher script:

```bash
oc rollout restart deployment/node-readiness-watcher -n autoscale-node-automation
```

## Verification & Testing

### 1. Tail Webhook Application Logs

```bash
oc logs -f -l app=machine-taint-webhook -n openshift-machine-api  
oc logs -f deployment/node-readiness-watcher -n autoscale-node-automation
oc get jobs -n autoscale-node-automation -w
oc logs -n autoscale-node-automation -l app=app-node-onboarding -f
```

### 2. Scale Up Worker MachineSet

```bash
oc scale machineset <WORKER_MACHINESET_NAME> --replicas=4 -n openshift-machine-api  
```

### 3. Verify Taint Injection on Machine Object

Observe new machine creation and verify the `network.zero-trust.io/firewall-unverified` taint is present in the spec:

```bash
# Get newly provisioning machine  
oc get machines.machine -n openshift-machine-api  
  
# Inspect taints section  
oc get machines.machine <NEW_MACHINE_NAME> -n openshift-machine-api -o yaml | grep -A 5 taints  
```

Expected Output:

```yaml
taints:  
  - effect: NoSchedule  
    key: network.zero-trust.io/firewall-unverified  
    value: "true"  
```

> [!IMPORTANT]
> The `Machine` resource will still transition to `Running` status normally. The `NoSchedule` taint restricts the Kubernetes Pod Scheduler from scheduling workloads until downstream validation succeeds. To validate the Taint on the Machine and  Node, check the resources before the Node reaches the `Ready` state or you may miss validating the Taint before AAP removes it.

### 4. Verify AAP Workflow Execution and Removal of Taint from Node and Machine

Observe that the new node is detected when fully ready by the watcher and the job is created to call AAP and run the workflow.

## Troubleshooting Matrix

| Symptom / Error | Cause | Resolution |
| :--- | :--- | :--- |
| `Error: building at STEP "RUN go mod download": go.mod requires go >= X` | Host Go version generated a `go.mod` newer than the container builder image. | Updated Dockerfile base image to `ubi9/go-toolset:latest` to match toolchain requirements. |
| `ErrImagePull` / `ImagePullBackOff` | Container image hosted in private registry without cluster pull credentials. | Created `quay-pull-secret` and linked to default `ServiceAccount` via `oc secrets link`. |
| `failed calling webhook: context deadline exceeded (10s timeout)` | OpenShift `openshift-machine-api` namespace enforces default-deny `NetworkPolicy`. | Applied custom `NetworkPolicy` (`allow-ingress-machine-webhook`) opening TCP port 8443 to the webhook deployment. |
| `http2: panic serving: runtime error: invalid memory address or nil pointer dereference` | `AdmissionReview.Request` evaluated to nil on health checks or non-admission requests. | Added strict nil checks (`if req == nil / len(req.Object.Raw) == 0`) before unmarshaling payloads. |
