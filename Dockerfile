FROM python:3.10-slim
RUN apt-get update
RUN apt-get update && apt-get install -y \
    curl \
    python3-dev \
    autoconf \
    g++ \
    libpq-dev \
    build-essential \
    automake \
    pkg-config \
    libtool \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"
WORKDIR /app
COPY . .
RUN poetry config virtualenvs.create false
RUN poetry install --no-dev --no-root
CMD ["poetry", "run", "mint"]
