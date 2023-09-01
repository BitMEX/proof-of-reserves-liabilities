FROM ubuntu:20.04 as builder
RUN export DEBIAN_FRONTEND=noninteractive; export TZ=America/New_York; \
    apt-get update && apt-get install python3.9 python3-pip python-is-python3\
    curl git-all wget python-apt -y

RUN mkdir /app
ARG BITCOINVER=0.21.0
RUN cd /app && \
    wget -q https://bitcoincore.org/bin/bitcoin-core-${BITCOINVER}/bitcoin-${BITCOINVER}-x86_64-linux-gnu.tar.gz && \
    tar -xf bitcoin-${BITCOINVER}-x86_64-linux-gnu.tar.gz && \
    cp bitcoin-${BITCOINVER}/bin/* .
COPY requirements.txt requirements.dev.txt /app/
RUN pip3 install -r /app/requirements.txt -r /app/requirements.dev.txt
COPY validate_reserves.py /app/validate_reserves.py
COPY test/test_reserves.py /app/test_reserves.py
RUN python /app/test_reserves.py
COPY generate_liabilities.py /app/generate_liabilities.py
COPY validate_liabilities.py /app/validate_liabilities.py
COPY test/test_liabilities.py /app/test_liabilities.py
RUN python /app/test_liabilities.py
RUN black --check /app/*.py
