FROM node:18-alpine

WORKDIR /app

COPY src ./src
COPY package.json package-lock.json webpack.config.js ./

RUN npm ci
CMD npm start

