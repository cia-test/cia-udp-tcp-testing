from python:3.11-slim-bookworm

WORKDIR /work

copy requirements.txt /work/
RUN pip install --no-cache-dir -r requirements.txt

copy src/* /work/

ENV SERVICE_NAME="cia-testrunner"

RUN adduser --uid 2000 \
	--no-create-home \
	--shell /bin/false \
	--disabled-password \
	$SERVICE_NAME

USER $SERVICE_NAME

CMD python3 -u server.py
