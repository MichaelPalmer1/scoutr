FROM python:3.8.6

RUN mkdir /api
WORKDIR /api

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["uwsgi", "--http", ":80", "--module", "main:app"]
