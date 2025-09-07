FROM gcc:latest

RUN apt-get update && apt-get install -y \
    clang \
    cppcheck \
    flawfinder \
    splint \
    python3 \
    python3-pip \
    python3-venv \
    bc \
    jq \
    default-libmysqlclient-dev \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install semgrep && \
    ln -s /opt/venv/bin/semgrep /usr/local/bin/semgrep

WORKDIR /code

COPY analyze.sh /usr/local/bin/analyze.sh
RUN dos2unix /usr/local/bin/analyze.sh && \
    chmod +x /usr/local/bin/analyze.sh

ENTRYPOINT ["/usr/local/bin/analyze.sh"]