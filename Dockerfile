FROM node:20-alpine

# Install system dependencies for native bindings
RUN apk add --no-cache \
    python3 \
    make \
    g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --production=false

# Copy source code
COPY src ./src
COPY wasm ./wasm

# Build TypeScript
RUN npm run build

# Prune dev dependencies
RUN npm prune --production

# Set environment
ENV NODE_ENV=production

# Run CLI
CMD ["node", "dist/cli/index.js", "help"]
