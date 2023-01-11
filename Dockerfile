from python

WORKDIR /work
copy src/* /work/

CMD python3 server.py
