FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
RUN apk add --no-cache iptables
COPY . .
EXPOSE 4000
CMD ["node", "server.js"]
