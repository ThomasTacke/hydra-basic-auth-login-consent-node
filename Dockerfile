# Build: TypeScript -> dist/
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS build
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --silent
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Run: production dependencies, compiled code, templates and static files only
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
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
