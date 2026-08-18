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
  - [2. Application Manifests (`webhook-deployment.yaml`)](#2-application-manifests-webhook-deploymentyaml)  
  - [3. Mutating Webhook Registration (`webhook-config.yaml`)](#3-mutating-webhook-registration-webhook-configyaml)  
- [Verification & Testing](#verification--testing)  
- [Troubleshooting Matrix](#troubleshooting-matrix)  
  
---  
  
## Overview  
  
In zero-trust environments, worker nodes booted by the Cluster Autoscaler cannot route traffic cleanly until physical or software firewall controllers process the new node IP address. By intercepting node creation at the `Machine` resource layer, this project guarantees that newly launched nodes remain in a quarantined `NoSchedule` state until automated security checks confirm network connectivity.  
  
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
2. **Firewall Automation:** The machine boots and enters `Running` status. An automation controller detects the assigned IP and configures external firewall rules.
3. **Validation & Release:** A verification DaemonSet tolerates the taint, runs connectivity probes, and removes the taint once network access is verified.

## Key Features

- **Dynamic JSON Patching:** Mutates incoming Machine objects to append the zero-trust quarantine taint without overwriting existing taints.
- **Automated TLS Integration:** Leverages OpenShift's native service-ca operator to handle certificate generation, signing, and CA bundle injection.
- **Strict Security Compliance:** Configured with explicit NetworkPolicy ingress rules to function inside OpenShift's default-deny `openshift-machine-api` namespace.
- **Defensive Runtime:** Guarded against nil-pointer panics caused by health probes or malformed API requests.

## Project Structure

```plaintext
webhook-project/  
├── main.go                 # Go HTTP server handling AdmissionReview logic  
├── go.mod                  # Go module definition (v1.22+)  
├── go.sum                  # Dependency lockfile  
├── Dockerfile              # Multi-stage UBI build configuration  
├── webhook-deployment.yaml # Kubernetes Deployment, Service, and NetworkPolicy  
└── webhook-config.yaml     # MutatingWebhookConfiguration manifest  
```

## Prerequisites

- OpenShift Cluster (v4.x) with `cluster-admin` access.
- OpenShift CLI (`oc`) installed.
- Container engine (`podman` or `docker`).
- Access to an enterprise container registry (e.g., Quay.io).

## Step 1: Webhook Implementation & Build

### Go Source Code (`main.go`)

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

### Multi-Stage Container Build (`Dockerfile`)

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

```bash
# Set target registry tag  
REGISTRY_URL="quay.io/your-org/machine-taint-webhook:latest"  
  
# Build and push container  
podman build -t ${REGISTRY_URL} .  
podman push ${REGISTRY_URL}  
```

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
> Create this secret as approprirate if required for the cluster's container registry.  If the repository is public, skip this step.

---

### 2. Application Manifests (`webhook-deployment.yaml`)

This bundle provisions the workload, network endpoints, security policies, and TLS certificate generation.

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

### 3. Mutating Webhook Registration (`webhook-config.yaml`)

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

### Apply Manifests

Apply the deployment and registration files to the cluster:

```bash
oc apply -f webhook-deployment.yaml  
oc apply -f webhook-config.yaml  
```

## Verification & Testing

### 1. Tail Webhook Application Logs

```bash
oc logs -f -l app=machine-taint-webhook -n openshift-machine-api  
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
> The `Machine` resource will still transition to `Running` status normally. The `NoSchedule` taint restricts the Kubernetes Pod Scheduler from scheduling workloads until downstream validation succeeds.

## Troubleshooting Matrix

| Symptom / Error | Cause | Resolution |
| :--- | :--- | :--- |
| `Error: building at STEP "RUN go mod download": go.mod requires go >= X` | Host Go version generated a `go.mod` newer than the container builder image. | Updated Dockerfile base image to `ubi9/go-toolset:latest` to match toolchain requirements. |
| `ErrImagePull` / `ImagePullBackOff` | Container image hosted in private registry without cluster pull credentials. | Created `quay-pull-secret` and linked to default `ServiceAccount` via `oc secrets link`. |
| `failed calling webhook: context deadline exceeded (10s timeout)` | OpenShift `openshift-machine-api` namespace enforces default-deny `NetworkPolicy`. | Applied custom `NetworkPolicy` (`allow-ingress-machine-webhook`) opening TCP port 8443 to the webhook deployment. |
| `http2: panic serving: runtime error: invalid memory address or nil pointer dereference` | `AdmissionReview.Request` evaluated to nil on health checks or non-admission requests. | Added strict nil checks (`if req == nil / len(req.Object.Raw) == 0`) before unmarshaling payloads. |
