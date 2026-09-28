FROM node:22-slim
WORKDIR /app
COPY . .
ENV DB_FILE=/data/karfarma.db PORT=3000
VOLUME /data
EXPOSE 3000
CMD ["node", "server.js"]
