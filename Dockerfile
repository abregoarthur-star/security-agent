FROM node:20-slim

WORKDIR /app

ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Railway assigns PORT dynamically
EXPOSE ${PORT:-3006}

CMD ["node", "src/index.js"]
