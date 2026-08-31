FROM golang:1.24-alpine3.20 AS build
RUN apk --no-cache add git file gcc musl-dev ca-certificates

# Create a non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN go build -buildvcs=false -a -ldflags="-s -w -extldflags=-static -linkmode external"  -o out ./approval-service

FROM alpine:3.20 AS scan
RUN apk update; apk --no-cache add --upgrade libssl3

# Create the same non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

COPY --from=build --chown=1001:1001 /src/out /approval-service
COPY --from=build --chown=1001:1001 /src/cue.mod cue.mod/
COPY --from=build --chown=1001:1001 /src/infra/config infra/config/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

FROM scratch

# Copy user information from scan stage
COPY --from=scan /etc/passwd /etc/passwd
COPY --from=scan /etc/group /etc/group

# Copy files with proper ownership
COPY --from=build --chown=1001:1001 /src/out /approval-service
COPY --from=build --chown=1001:1001 /src/cue.mod cue.mod/
COPY --from=build --chown=1001:1001 /src/infra/config infra/config/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Switch to non-root user
USER 1001:1001

ENV AWS_DEFAULT_REGION="us-east-1"
ENTRYPOINT [ "/approval-service" ]