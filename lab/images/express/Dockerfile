FROM node:22.23.5-alpine
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev --no-audit --no-fund
COPY app.js .
ENV NODE_ENV=development
CMD ["node", "app.js"]
