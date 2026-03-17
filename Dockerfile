FROM node:20-slim

WORKDIR /app

ENV NODE_ENV=production

# Phase 2 (Nuclei) deferred — install separately when needed
# Phase 1 passive validation has zero binary dependencies

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Railway assigns PORT dynamically
EXPOSE ${PORT:-3006}

CMD ["node", "src/index.js"]
