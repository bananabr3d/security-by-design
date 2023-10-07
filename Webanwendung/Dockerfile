FROM python:3.11-slim-buster

WORKDIR /app

COPY ./ ./
ENV PYTHONUNBUFFERED=1
RUN pip3 install -r requirements.txt

CMD [ "python", "-m", "flask", "--app", "run", "run" ]