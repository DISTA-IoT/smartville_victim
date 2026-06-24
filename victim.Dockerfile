FROM python:3.13.3-slim


# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl tcpdump tcpreplay netcat-openbsd wget \
    net-tools iputils-ping git build-essential \
    && rm -rf /var/lib/apt/lists/*

# Full rebuild bust: pass CACHE_BUST=<timestamp> to re-run pip install and code clone
ARG CACHE_BUST=1

RUN pip install --upgrade pip

# Install dependencies from the build context (submodule checkout on disk)
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Code-only bust: pass CODE_BUST=<timestamp> to re-run only the git clone, keeping pip cached
ARG CODE_BUST=1

# Clone the repo
RUN git clone -b new_smartville https://github.com/DISTA-IoT/smartville_victim.git /victim

WORKDIR /victim
