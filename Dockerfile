from python:3.11-slim-bookworm

WORKDIR /work
copy src/* /work/

CMD python3 server.py
