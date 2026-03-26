FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 8002
CMD ["npx", "ts-node", "src/server.ts"]
