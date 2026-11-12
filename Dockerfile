FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py index.html ./
COPY icons ./icons
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 8000
# one worker: the unlocked key lives in this process's memory only
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:8000", "app:app"]
