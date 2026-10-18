FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pki ./pki
COPY app ./app
COPY tests ./tests
ENV PYTHONUNBUFFERED=1