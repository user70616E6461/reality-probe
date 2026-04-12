FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY reality_probe.py .

EXPOSE 7890

CMD ["python", "reality_probe.py"]
