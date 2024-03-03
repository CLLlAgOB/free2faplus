FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
COPY ./templates/ ./templates/ 
COPY ./dictionary ./dictionary
COPY ./static/    ./static/
COPY ./files/ ./
RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x ./entrypoint.sh

RUN groupadd -r appuser && useradd --create-home -r -g appuser appuser

RUN chown -R appuser:appuser /app

EXPOSE 8010

ENTRYPOINT ["./entrypoint.sh"]