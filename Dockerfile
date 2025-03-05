FROM python:3.10-slim
RUN apt-get update
RUN apt-get install -y curl python3-dev autoconf g++
RUN apt-get install -y libpq-dev

# Deps for building secp256k1-py
RUN apt-get install -y build-essential automake pkg-config libtool libffi-dev

RUN curl -sSL https://install.python-poetry.org | python3 - --version 1.8.5
ENV PATH="/root/.local/bin:$PATH"
WORKDIR /app
COPY . .
RUN poetry config virtualenvs.create false
RUN poetry install --no-dev --no-root
