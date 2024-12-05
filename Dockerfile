# syntax=docker/dockerfile:1
ARG GO_VERSION="1.23"

# Step 1: Build Stage
# Use the official Go image to build the binary
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

WORKDIR /build

RUN apk add git

# Cache dependencies
COPY go.mod ./
RUN --mount=type=cache,target=/root/.cache/go-build go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath


# Step 2: Runtime Stage
# Use a lightweight distroless image
FROM gcr.io/distroless/static-debian12:latest

# Set non-root user for execution
USER nonroot:nonroot

# Copy the built binary from the build stage
COPY --from=builder /build/gontppool /gontppool

# Expose the default NTP port
EXPOSE 123/udp

# Command to run the NTP server
ENTRYPOINT ["/gontppool"]