# Dockerfile
FROM node:20-alpine

# 1. Create app directory
WORKDIR /usr/src/app

# 2. Install production dependencies
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts


# 3. Copy source & build
COPY . .
RUN npm run build

# 4. Expose port & run
EXPOSE 4000
CMD ["node", "dist/server.js"]
