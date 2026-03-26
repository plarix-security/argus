FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create output directory
RUN mkdir -p /app/output

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["What is the weather like today?"]
