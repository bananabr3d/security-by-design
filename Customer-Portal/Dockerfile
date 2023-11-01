FROM python:3.11-slim-buster

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

COPY ./ ./
ENV PYTHONUNBUFFERED=1

CMD [ "python3", "run.py"]