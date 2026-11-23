FROM node:20-slim AS build
RUN npm ci

FROM python:3.13-slim
WORKDIR /app
COPY . .
RUN useradd --create-home app
USER app
CMD ["gunicorn", "app:app"]
