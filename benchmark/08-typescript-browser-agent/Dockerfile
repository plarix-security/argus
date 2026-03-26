FROM mcr.microsoft.com/playwright:v1.40.0-jammy
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ENTRYPOINT ["npx", "ts-node", "src/main.ts"]
