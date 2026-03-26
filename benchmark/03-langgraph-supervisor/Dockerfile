FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/workspace
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "src.main"]
