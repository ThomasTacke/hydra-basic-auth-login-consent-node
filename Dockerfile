# Build: TypeScript -> dist/
FROM node:24-alpine AS build
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --silent
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Run: production dependencies, compiled code, templates and static files only
FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --silent && npm cache clean --force
COPY --from=build /usr/src/app/dist ./dist
COPY views ./views
COPY public ./public

# Unprivileged user that comes with the node image
USER node
EXPOSE 3000
CMD ["node", "dist/app.js"]
