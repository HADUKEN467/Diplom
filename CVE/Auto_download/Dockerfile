FROM python:latest

WORKDIR /app

RUN apt-get update && apt-get install -y git

RUN pip install fastapi uvicorn pymongo pydantic requests

COPY . .

EXPOSE 8000

CMD ["python", "main.py"]