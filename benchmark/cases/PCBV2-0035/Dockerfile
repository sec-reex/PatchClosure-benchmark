ARG NODE_VERSION=20.15.0
FROM node:${NODE_VERSION}

RUN mkdir -p /app /tmp/allowed
COPY server.js /app/server.js

WORKDIR /app
EXPOSE 3000
CMD ["node", "/app/server.js"]
