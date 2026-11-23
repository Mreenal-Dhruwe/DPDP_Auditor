FROM node:20-slim AS build
USER node
RUN npm ci

FROM python:3.13-slim
WORKDIR /app
COPY . .
CMD ["gunicorn", "app:app"]
