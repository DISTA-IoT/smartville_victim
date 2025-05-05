FROM python:3.13.3-slim


# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl tcpdump tcpreplay netcat-openbsd wget \
    net-tools iputils-ping git build-essential \
    && rm -rf /var/lib/apt/lists/*


# Clone the repo
RUN git clone https://github.com/DISTA-IoT/smartville_victim.git /victim

WORKDIR /victim

# Install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt