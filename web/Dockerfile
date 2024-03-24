FROM node:18-alpine

WORKDIR /app

COPY package.json package-lock.json webpack.config.js ./
RUN npm ci

COPY src ./src

CMD npm start

