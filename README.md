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
- [Key Features](#key-features)  
- [Project Structure](#project-structure)  
- [Prerequisites](#prerequisites)  
- [Step 1: Webhook Implementation & Build](#step-1-webhook-implementation--build)  
  - [Go Source Code (`main.go`)](#go-source-code-maingo)  
  - [Multi-Stage Container Build (`Dockerfile`)](#multi-stage-container-build-dockerfile)  
- [Step 2: Deployment & Configuration](#step-2-deployment--configuration)  
  - [1. Cluster Pull Credentials](#1-cluster-pull-credentials)  
  - [2. Application Manifests (`webhook-deployment.yml`)](#2-application-manifests-webhook-deploymentyml)  
  - [3. Mutating Webhook Registration (`webhook-config.yml`)](#3-mutating-webhook-registration-webhook-configyml)  
- [Verification & Testing](#verification--testing)  
- [Troubleshooting Matrix](#troubleshooting-matrix)  
  
---  
  
## Overview  
  
In zero-trust environments, worker nodes booted by the Cluster Autoscaler cannot route traffic cleanly until physical or software firewall controllers process the new node IP address. By intercepting node creation at the `Machine` resource layer, this project guarantees that newly launched nodes remain in a quarantined `NoSchedule` state until automated security checks confirm network connectivity. After the node is created, a watcher pod will detect the newly created node and execute a job that uses the AAP API to call a workflow job template that untaints the node for operation.  This workflow can be customized to perform additional work prior to removing the taint.  For example, the firewall for the zero-trust environment can be updated for the newly created node, and the firewall can be validated prior to removing the taint.
  
---  
  
## Architecture & Workflow  
  
```text  
+-----------------------+ 1. Intercept CREATE +-----------------------------+  
| Cluster Autoscaler    | -------------------> | Mutating Webhook Server     |  
| (Machine API)         |                      | (Injects Zero-Trust Taint)  |  
+-----------------------+                      +-----------------------------+  
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

1. **Node Interception & Quarantine:** The Webhook mutates new Machine resources to apply `network.zero-trust.io/firewall-unverified=true:NoSchedule`.
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
├── Containerfile                    # Containerfile to build Go HTTP server container
├── main.go                          # Go HTTP server handling AdmissionReview logic  
├── go.mod                           # Go module definition (v1.22+)  
├── go.sum                           # dependency lockfile  
├── manifests                        # 
│    └── watcher-and-job-rbac.yml    # OpenShift namespace, serviceaccounts, rbac, and deployment  
│    └── webhook-deployment.yml      # OpenShift deployment, service, and networkPolicy  
│    └── webhook-config.yml.yml      # OpenShift mutatingwebhookconfiguration manifest
├── playbooks                        # 
│    └── remove-autoscale-taint.yml  # Ansible playbook to remove machine and node taint
└── README.md                        # project documentation
```

## Prerequisites

- OpenShift Cluster (v4.x) with `cluster-admin` access.
- OpenShift CLI (`oc`) installed.
- Container engine (`podman` or `docker`).
- Go programming tools installed for initial build
- Access to an enterprise container registry (e.g., Quay.io).

## Step 1: Webhook Implementation & Build

### 1. Initialize Go Module & Dependencies (`go.mod` & `go.sum`)

Before compiling or building the container image, initialize the Go module and download the Kubernetes admission library dependencies to generate `go.mod` and `go.sum`.

```bash
# Initialize the Go module
go mod init autoscale-webhook

# Add required Kubernetes & OpenShift API dependencies
go get k8s.io/api/admission/v1 \
       k8s.io/apimachinery/pkg/apis/meta/v1 \
       k8s.io/apimachinery/pkg/runtime \
       k8s.io/apimachinery/pkg/runtime/serializer

# Tidy and generate the go.sum dependency lockfile
go mod tidy
```

> [!NOTE]
> Download the built artifacts or run these steps manually to ensure the files are up to date.

---
### 2. Go Source Code (`main.go`)

The handler unmarshals incoming AdmissionReview requests, validates payload integrity, and generates a JSON Patch adding the quarantine taint:

```go
package main  
  
import (  
	"encoding/json"  
	"io"  
	"log"  
	"net/http"  
  
	admissionv1 "k8s.io/api/admission/v1"  
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"  
	"k8s.io/apimachinery/pkg/runtime"  
	"k8s.io/apimachinery/pkg/runtime/serializer"  
)  
  
var (  
	runtimeScheme = runtime.NewScheme()  
	codecs        = serializer.NewCodecFactory(runtimeScheme)  
	deserializer  = codecs.UniversalDeserializer()  
)  
  
type MachineSpec struct {  
	Taints []Taint `json:"taints,omitempty"`  
}  
  
type Machine struct {  
	Spec MachineSpec `json:"spec"`  
}  
  
type Taint struct {  
	Key    string `json:"key"`  
	Value  string `json:"value"`  
	Effect string `json:"effect"`  
}  
  
type PatchOperation struct {  
	Op    string      `json:"op"`  
	Path  string      `json:"path"`  
	Value interface{} `json:"value,omitempty"`  
}  
  
func mutateHandler(w http.ResponseWriter, r *http.Request) {  
	log.Println("Received admission review request")  
  
	body, err := io.ReadAll(r.Body)  
	if err != nil {  
		log.Printf("Error reading request body: %v", err)  
		http.Error(w, "Failed to read request body", http.StatusBadRequest)  
		return  
	}  
  
	admissionReview := admissionv1.AdmissionReview{}  
	if _, _, err := deserializer.Decode(body, nil, &admissionReview); err != nil {  
		log.Printf("Error decoding admission review: %v", err)  
		http.Error(w, "Failed to decode admission review", http.StatusBadRequest)  
		return  
	}  
  
	req := admissionReview.Request  
	if req == nil {  
		log.Println("Error: AdmissionReview request field is nil")  
		http.Error(w, "AdmissionReview request object missing", http.StatusBadRequest)  
		return  
	}  
  
	if len(req.Object.Raw) == 0 {  
		log.Println("Error: AdmissionReview request Object.Raw is empty")  
		http.Error(w, "AdmissionReview raw object missing", http.StatusBadRequest)  
		return  
	}  
  
	log.Printf("Intercepted creation request for Machine: %s/%s", req.Namespace, req.Name)  
  
	var machine Machine  
	if err := json.Unmarshal(req.Object.Raw, &machine); err != nil {  
		log.Printf("Error unmarshaling Machine object: %v", err)  
		http.Error(w, "Failed to unmarshal Machine object", http.StatusBadRequest)  
		return  
	}  
  
	targetTaint := Taint{  
		Key:    "network.zero-trust.io/firewall-unverified",  
		Value:  "true",  
		Effect: "NoSchedule",  
	}  
  
	var patches []PatchOperation  
	if len(machine.Spec.Taints) == 0 {  
		patches = append(patches, PatchOperation{  
			Op:    "add",  
			Path:  "/spec/taints",  
			Value: []Taint{targetTaint},  
		})  
	} else {  
		patches = append(patches, PatchOperation{  
			Op:    "add",  
			Path:  "/spec/taints/-",  
			Value: targetTaint,  
		})  
	}  
  
	patchBytes, err := json.Marshal(patches)  
	if err != nil {  
		log.Printf("Error marshaling patch: %v", err)  
		http.Error(w, "Failed to marshal patch", http.StatusInternalServerError)  
		return  
	}  
  
	patchType := admissionv1.PatchTypeJSONPatch  
	admissionResponse := &admissionv1.AdmissionResponse{  
		Allowed:   true,  
		Patch:     patchBytes,  
		PatchType: &patchType,  
	}  
  
	responseReview := admissionv1.AdmissionReview{  
		TypeMeta: metav1.TypeMeta{  
			APIVersion: "admission.k8s.io/v1",  
			Kind:       "AdmissionReview",  
		},  
		Response: admissionResponse,  
	}  
	responseReview.Response.UID = req.UID  
  
	respBytes, err := json.Marshal(responseReview)  
	if err != nil {  
		log.Printf("Error marshaling response: %v", err)  
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)  
		return  
	}  
  
	log.Println("Successfully generated taint patch and responded to API server")  
	w.Header().Set("Content-Type", "application/json")  
	w.Write(respBytes)  
}  
  
func main() {  
	http.HandleFunc("/mutate", mutateHandler)  
	log.Println("Starting mutating webhook server on port 8443...")  
	if err := http.ListenAndServeTLS(":8443", "/etc/webhook/certs/tls.crt", "/etc/webhook/certs/tls.key", nil); err != nil {  
		log.Fatalf("Failed to listen and serve: %v", err)  
	}  
}  
```

### 3. Multi-Stage Container Build (`Dockerfile`)

Builds using Red Hat Enterprise Linux UBI Toolset and outputs a UBI Minimal runtime image:

```dockerfile
# Stage 1: Build binary using Red Hat Go Toolset  
FROM registry.access.redhat.com/ubi9/go-toolset:latest AS builder  
WORKDIR /opt/app-root/src  
  
COPY go.mod go.sum ./  
RUN go mod download  
  
COPY main.go ./  
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o webhook main.go  
  
# Stage 2: Create minimal runtime image  
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest  
WORKDIR /  
  
COPY --from=builder /opt/app-root/src/webhook /webhook  
  
USER 65532:65532  
ENTRYPOINT ["/webhook"]  
```

### 4. Build and Push Container Image

```bash
# Set target registry tag  
REGISTRY_URL="quay.io/your-org/machine-taint-webhook:latest"  
  
# Build and push container  
podman build -t ${REGISTRY_URL} .  
podman push ${REGISTRY_URL}  
```

> [!NOTE]
> Set REGISTRY_URL to your container registry.

## Step 2: Deployment & Configuration

Deploying the webhook into the `openshift-machine-api` namespace requires specific OpenShift annotations and network policies to ensure secure HTTPS communication and cluster connectivity.

### Manifest Breakdown & Architectural Requirements

| Component | Resource | Purpose & Why It Is Required |
| :--- | :--- | :--- |
| **Pull Credentials** | `Secret` & `ServiceAccount` | Authorizes pod image pulls from private registries. Linking to the `default` ServiceAccount avoids inline `imagePullSecrets` modifications. |
| **Webhook Service Annotation** | `Service` | **Required for TLS Certificate Generation:** Annotating the Service with `service.beta.openshift.io/serving-cert-secret-name` triggers OpenShift's `service-ca` operator to automatically generate a TLS cert/key pair in Secret `machine-taint-webhook-tls`. |
| **Ingress NetworkPolicy** | `NetworkPolicy` | **Required for Network Access:** The `openshift-machine-api` namespace enforces strict default-deny network rules. Without explicitly permitting ingress TCP traffic on port `8443`, calls from the API server hit a 10s deadline timeout. |
| **MutatingWebhook Registration** | `MutatingWebhookConfiguration` | **Required for CA Trust Chain:** Intercepts `CREATE` operations on `Machine` resources. Annotated with `service.beta.openshift.io/inject-cabundle: "true"` so OpenShift automatically populates the `caBundle` trust field. |

---

### 1. Cluster Pull Credentials

Create the pull secret in `openshift-machine-api` and link it to the default `ServiceAccount`:

```bash
oc create secret docker-registry quay-pull-secret \  
  --docker-server=quay.io \  
  --docker-username="<YOUR_QUAY_USERNAME>" \  
  --docker-password="<YOUR_QUAY_TOKEN>" \  
  --docker-email="<YOUR_EMAIL>" \  
  -n openshift-machine-api  
  
oc secrets link default quay-pull-secret --for=pull -n openshift-machine-api  
```

> [!NOTE]
> Create this secret as approprirate for your container registry.  If the repository is public, skip this step.

---

### 2. Application Manifests (`webhook-deployment.yml`)

This bundle provisions the workload, network endpoints, security policies, and TLS certificate generation for the Mutating Admission Webhook.

```yaml
apiVersion: apps/v1  
kind: Deployment  
metadata:  
  name: machine-taint-webhook  
  namespace: openshift-machine-api  
  labels:  
    app: machine-taint-webhook  
spec:  
  replicas: 2  
  selector:  
    matchLabels:  
      app: machine-taint-webhook  
  template:  
    metadata:  
      labels:  
        app: machine-taint-webhook  
    spec:  
      containers:  
        - name: webhook  
          image: quay.io/your-org/machine-taint-webhook:latest  
          ports:  
            - containerPort: 8443  
          volumeMounts:  
            - name: webhook-certs  
              mountPath: /etc/webhook/certs  
              readOnly: true  
      volumes:  
        - name: webhook-certs  
          secret:  
            secretName: machine-taint-webhook-tls  
---  
apiVersion: v1  
kind: Service  
metadata:  
  name: machine-taint-webhook-service  
  namespace: openshift-machine-api  
  annotations:  
    # REQUIRED: Tells OpenShift service-ca operator to create secret "machine-taint-webhook-tls" 
    # containing signed tls.crt and tls.key files.
    service.beta.openshift.io/serving-cert-secret-name: machine-taint-webhook-tls  
spec:  
  ports:  
    - port: 443  
      targetPort: 8443  
  selector:  
    app: machine-taint-webhook  
---  
apiVersion: networking.k8s.io/v1  
kind: NetworkPolicy  
metadata:  
  name: allow-ingress-machine-webhook  
  namespace: openshift-machine-api  
spec:  
  podSelector:  
    matchLabels:  
      app: machine-taint-webhook  
  ingress:  
    # REQUIRED: Opens port 8443 through openshift-machine-api default-deny firewall.
    # Prevents "context deadline exceeded (10s timeout)" errors during API interception.
    - ports:  
        - protocol: TCP  
          port: 8443
  policyTypes:  
    - Ingress  
```

#### Why These Resources Are Configured This Way:

* **Why Service Annotation is Required (`service.beta.openshift.io/serving-cert-secret-name`):**  
  Kubernetes Mutating Webhooks **must** communicate over HTTPS. Instead of manually deploying `cert-manager` or managing custom SSL certificates, this annotation instructs OpenShift's internal `service-ca` operator to automatically issue a trusted TLS certificate authority and server certificate, binding them directly to Secret `machine-taint-webhook-tls`. The webhook Deployment then mounts this Secret to `/etc/webhook/certs`.

* **Why NetworkPolicy is Required (`allow-ingress-machine-webhook`):**  
  Core OpenShift namespaces like `openshift-machine-api` run default-deny NetworkPolicies for platform hardening. Without this `NetworkPolicy` explicitly allowing ingress on port `8443`, packets sent from the Kubernetes API server to the webhook pod are dropped, causing API scale operations to fail with `failed calling webhook: context deadline exceeded`.

---

### 3. Mutating Webhook Registration (`webhook-config.yml`)

Registers the admission endpoint with the OpenShift Control Plane.

```yaml
apiVersion: admissionregistration.k8s.io/v1  
kind: MutatingWebhookConfiguration  
metadata:  
  name: machine-taint-injector-webhook  
  annotations:  
    # REQUIRED: Tells OpenShift service-ca operator to auto-inject cluster CA bundle into caBundle.
    service.beta.openshift.io/inject-cabundle: "true"  
webhooks:  
  - name: taint-injector.zero-trust.io  
    rules:  
      - apiGroups: ["machine.openshift.io"]  
        apiVersions: ["v1beta1"]  
        operations: ["CREATE"]  
        resources: ["machines"]  
        scope: "Namespaced"  
    clientConfig:  
      service:  
        name: machine-taint-webhook-service  
        namespace: openshift-machine-api  
        path: "/mutate"  
    admissionReviewVersions: ["v1"]  
    sideEffects: None  
    failurePolicy: Fail  
```

#### Why CA Bundle Injection is Required (`service.beta.openshift.io/inject-cabundle`):

For the Kubernetes API Server to validate the TLS certificate presented by `machine-taint-webhook-service`, it requires a valid CA certificate in `clientConfig.caBundle`. Setting this annotation instructs OpenShift to automatically populate the `caBundle` field with the cluster’s internal CA, completing the end-to-end TLS trust chain.

---

### 4.  Watcher Application Manifests (`watcher-and-job-rbac.yml`)

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
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aap-node-management-sa
  namespace: autoscale-node-automation
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aap-node-management-role
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "patch", "update"]
  - apiGroups: ["machine.openshift.io"]
    resources: ["machines"]
    verbs: ["get", "list", "patch", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: aap-node-management-binding
subjects:
  - kind: ServiceAccount
    name: aap-node-management-sa
    namespace: autoscale-node-automation
roleRef:
  kind: ClusterRole
  name: aap-node-management-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Secret
metadata:
  name: aap-node-management-token
  namespace: autoscale-node-automation
  annotations:
    kubernetes.io/service-account.name: aap-node-management-sa
type: kubernetes.io/service-account-token
---
apiVersion: v1
kind: Secret
metadata:
  name: aap-secret
  namespace: autoscale-node-automation
type: Opaque
stringData:
  token: "<AAP_AUTH_TOKEN>"
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

#### Why These Resources Are Configured This Way:

* **Why Provision a New Namespace:**  
  The Watcher application is user workload despite operating on system resources.  It is best practice to maintain this application in its own namespace.

* **Why Use ServiceAccounts and Cluster Roles (`node-readiness-watcher-role`,`aap-node-management-role`):**  
  The Watcher application must be able to stream Node events and spawn onboarding Jobs.  AAP must be able to modify Node and Machine resources.

* **Why Use Secrets (`aap-node-management-token`,`aap-secret`):**  
  Creating a secret for the ServiceAccount `aap-node-management-sa` allows for the creation of an API token that will be configured into an AAP credential allowing AAP to make changes to the OpenShift cluster.  Creating a Secret `aap-secret` allows the AAP API token to managed separately and not hardcoded into any manifests or scripts.

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

#### Why `watcher.py` is Managed as a Standalone File:

Managing the `watcher.py` Python script as a separate file allows it to be maintained without requring a custom container image rebuild.  It can be mounted into the Deployment allowing for changes to be made with a simple restart of the Deployment.

---

### Apply Manifests

Apply the Webhook deployment and registration files to the cluster:

```bash
oc apply -f webhook-deployment.yml  
oc apply -f webhook-config.yml  
```

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

Retrieve the ServceAccount API token for the AAP credential:

```bash
oc get secret aap-node-management-token -n autoscale-node-automation \
  -o jsonpath='{.data.token}' | base64 --decode
```

Create an `OpenShift or Kubernetes API Bearer Token` Credential in AAP.  Set the `OpenShift or Kubernetes API Endpoint` to the cluster API endpoint, and paste the decoded token in `API authenticated bearer token`.

## Verification & Testing

### 1. Tail Webhook Application Logs

```bash
oc logs -f -l app=machine-taint-webhook -n openshift-machine-api  
oc logs -f deployment/node-readiness-watcher -n autoscale-node-automation
oc get jobs -n autoscale-node-automation -w
oc lops -n autoscale-node-automation -l app=app-node-onboarding -f
```

### 2. Scale Up Worker MachineSet

```bash
oc scale machineset <WORKER_MACHINESET_NAME> --replicas=4 -n openshift-machine-api  
```

### 3. Verify Taint Injection on Machine Object

Observe new machine creation and verify the `network.zero-trust.io/firewall-unverified` taint is present in the spec:

```bash
# Get newly provisioning machine  
oc get machines -n openshift-machine-api  
  
# Inspect taints section  
oc get machine <NEW_MACHINE_NAME> -n openshift-machine-api -o yaml | grep -A 5 taints  
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
