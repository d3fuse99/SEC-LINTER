FROM python:3.12-alpine
WORKDIR /app
COPY . /app
EXPOSE 5006
CMD ["python", "server.py"]