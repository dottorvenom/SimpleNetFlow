FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/uploads

EXPOSE 9977

# gthread keeps status polling responsive while a PCAP is being uploaded/parsed.
# timeout 0 disables Gunicorn's worker silence timeout for long-running transfers.
CMD ["gunicorn", "--bind", "0.0.0.0:9977", "--worker-class", "gthread", "--workers", "1", "--threads", "8", "--timeout", "0", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
