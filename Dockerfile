# Build: TypeScript -> dist/
FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS build
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --silent
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Run: production dependencies, compiled code, templates and static files only
FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --silent && npm cache clean --force
COPY --from=build /usr/src/app/dist ./dist
COPY views ./views
COPY public ./public

# Profile store (mount a volume here) and the poste.io export (read-only mount)
RUN mkdir -p /data /claims && chown node:node /data

# Unprivileged user that comes with the node image
USER node
EXPOSE 3000
CMD ["node", "dist/app.js"]
