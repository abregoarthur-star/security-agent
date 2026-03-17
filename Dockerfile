FROM node:20-slim

WORKDIR /app

ENV NODE_ENV=production

# Phase 2: Add Nuclei binary for safe vulnerability detection (info/detection templates only)
RUN apt-get update && apt-get install -y --no-install-recommends wget unzip ca-certificates && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip && \
    unzip nuclei_linux_amd64.zip -d /usr/local/bin/ && \
    rm nuclei_linux_amd64.zip && \
    apt-get purge -y wget unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
RUN nuclei -update-templates -silent 2>/dev/null || true

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Railway assigns PORT dynamically
EXPOSE ${PORT:-3006}

CMD ["node", "src/index.js"]
