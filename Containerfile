# Stage 1: Build the Go binary using Red Hat Enterprise Linux UBI 9 Go Toolset
FROM registry.access.redhat.com/ubi9/go-toolset:latest AS builder

# Set working directory inside the default app-root directory for UBI images
WORKDIR /opt/app-root/src

# Copy dependency definitions
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./

# Compile static binary for Linux x86_64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o webhook main.go

# Stage 2: Create minimal runtime image
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

WORKDIR /

# Copy compiled binary from builder stage
COPY --from=builder /opt/app-root/src/webhook /webhook

# Run as non-root user (UID 65532) for OpenShift security compliance
USER 65532:65532

ENTRYPOINT ["/webhook"]
