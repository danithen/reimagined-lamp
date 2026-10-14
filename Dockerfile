# Build stage
FROM node:20-slim AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --legacy-peer-deps

# Copy source code
COPY . .

# Runtime stage
FROM node:20-slim

WORKDIR /app

# Copy only needed files from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/index.ts ./

# Install tsx globally for running the typescript file
RUN npm install -g tsx

# The app expects OLLAMA_BASE_URL to be provided at runtime
ENV OLLAMA_BASE_URL=http://host.docker.internal:11434

CMD ["tsx", "index.ts"]
