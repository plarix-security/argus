FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir -p /app/data
ENV NODE_ENV=production
ENTRYPOINT ["npx", "ts-node", "src/main.ts"]
