FROM python:3.9-slim

WORKDIR /app
COPY requirement.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirement.txt
COPY . .

CMD ["python", "-m", "src.agent"]