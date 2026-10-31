# Build: TypeScript -> dist/
FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --silent
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Run: production dependencies, compiled code, templates and static files only
FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85
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
