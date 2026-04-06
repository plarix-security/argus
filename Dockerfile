FROM node:20-alpine

# Install system dependencies for native bindings
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git

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

# Create temp directory for repo clones
RUN mkdir -p /tmp/wyscan-scans

# Set environment
ENV NODE_ENV=production
ENV PORT=3000

# Expose webhook port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Run the server
CMD ["node", "dist/app.js"]
