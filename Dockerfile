FROM python:3.9-slim
RUN apt-get update
RUN apt-get install -y curl python3-dev autoconf g++
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"
WORKDIR /app
COPY . .
RUN poetry config virtualenvs.create false
RUN poetry install --no-dev --no-root
EXPOSE 3338
CMD ["poetry", "run", "mint", "--port", "3338", "--host", "0.0.0.0"]