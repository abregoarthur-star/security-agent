FROM node:20-slim

WORKDIR /app

ENV NODE_ENV=production
ENV DATA_DIR=/data

# Phase 2: Nuclei — safe, detection-only vulnerability fingerprinting
RUN apt-get update && apt-get install -y --no-install-recommends wget unzip ca-certificates \
    && NUCLEI_VERSION=$(wget -qO- "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" | grep '"tag_name"' | cut -d'"' -f4) \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && apt-get purge -y wget unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Download detection-only templates (info + low severity)
RUN nuclei -update-templates -silent 2>/dev/null || true

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Railway assigns PORT dynamically
EXPOSE ${PORT:-3006}

CMD ["node", "src/index.js"]
