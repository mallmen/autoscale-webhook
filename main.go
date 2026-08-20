package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

type Config struct {
	TaintKey    string
	TaintValue  string
	TaintEffect string
	Port        string
	TLSCertPath string
	TLSKeyPath  string
	MutatePath  string
}

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
	cfg           Config
)

func init() {
	cfg = Config{
		TaintKey:    getEnv("TAINT_KEY", "network.zero-trust.io/firewall-unverified"),
		TaintValue:  getEnv("TAINT_VALUE", "true"),
		TaintEffect: getEnv("TAINT_EFFECT", "NoSchedule"),
		Port:        getEnv("PORT", "8443"),
		TLSCertPath: getEnv("TLS_CERT_PATH", "/etc/webhook/certs/tls.crt"),
		TLSKeyPath:  getEnv("TLS_KEY_PATH", "/etc/webhook/certs/tls.key"),
		MutatePath:  getEnv("MUTATE_PATH", "/mutate"),
	}
}

func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

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

	// Define the zero-trust quarantine taint using configurable options
	targetTaint := Taint{
		Key:    cfg.TaintKey,
		Value:  cfg.TaintValue,
		Effect: cfg.TaintEffect,
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
	http.HandleFunc(cfg.MutatePath, mutateHandler)
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Starting mutating webhook server on port %s using path %s...", cfg.Port, cfg.MutatePath)
	if err := http.ListenAndServeTLS(addr, cfg.TLSCertPath, cfg.TLSKeyPath, nil); err != nil {
		log.Fatalf("Failed to listen and serve: %v", err)
	}
}
