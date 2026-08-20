apiVersion: v1
kind: ServiceAccount
metadata:
  name: node-readiness-watcher-sa
  namespace: openshift-machine-api
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-readiness-watcher-role
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
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
    namespace: openshift-machine-api
roleRef:
  kind: ClusterRole
  name: node-readiness-watcher-role
  apiGroup: rbac.authorization.k8s.io
---
# RBAC for the dynamically spawned Job to untaint the node
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aap-onboarding-job-sa
  namespace: openshift-machine-api
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aap-onboarding-job-role
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "patch", "update"]
  - apiGroups: ["machine.openshift.io"]
    resources: ["machines"]
    verbs: ["get", "patch", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: aap-onboarding-job-binding
subjects:
  - kind: ServiceAccount
    name: aap-onboarding-job-sa
    namespace: openshift-machine-api
roleRef:
  kind: ClusterRole
  name: aap-onboarding-job-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: node-readiness-watcher
  namespace: openshift-machine-api
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
          image: registry.access.redhat.com/ubi9/python-39:latest
          command: ["/bin/sh", "-c"]
          args:
            - |
              pip install --quiet kubernetes
              python -u /app/watcher.py
          env:
            - name: WATCHER_NAMESPACE
              value: "openshift-machine-api"
            - name: AAP_HOST
              value: "aap.example.com"
            - name: WORKFLOW_ID
              value: "42"
          volumeMounts:
            - name: script
              mountPath: /app
      volumes:
        - name: script
          configMap:
            name: node-readiness-watcher-script
