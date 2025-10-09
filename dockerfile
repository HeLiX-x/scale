# Stage 1: Build the Go binary
# CORRECTED: Updated to Go 1.23 to match go.mod
FROM golang:1.23-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy Go modules and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application
# CGO_ENABLED=0 is important for creating a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /scale-server ./main.go

# Stage 2: Create the final, lightweight image
FROM alpine:latest

# Copy the built binary from the builder stage
COPY --from=builder /scale-server /scale-server

# Expose the port the app will run on.
# Cloud Run will automatically map this to 443 (HTTPS).
EXPOSE 8080

# Command to run the application
CMD ["/scale-server"]