FROM python:3.10-slim
COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /uvx /bin/
RUN apt-get update
RUN apt-get install -y curl python3-dev autoconf g++
RUN apt-get install -y libpq-dev

# Deps for building secp256k1-py
RUN apt-get install -y build-essential automake pkg-config libtool libffi-dev

ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV UV_PYTHON_DOWNLOADS=never
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /app
COPY . .
RUN uv sync --locked --no-dev
CMD ["mint"]
