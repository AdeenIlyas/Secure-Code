FROM openjdk:11

RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    curl \
    git \
    python3 \
    python3-pip \
    bc \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/spotbugs \
    && wget -q https://github.com/spotbugs/spotbugs/releases/download/4.7.3/spotbugs-4.7.3.zip \
    && unzip spotbugs-4.7.3.zip -d /opt \
    && rm spotbugs-4.7.3.zip \
    && ln -s /opt/spotbugs-4.7.3 /opt/spotbugs \
    && chmod +x /opt/spotbugs-4.7.3/bin/spotbugs

RUN mkdir -p /opt/findsecbugs \
    && wget -q https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.12.0/findsecbugs-cli-1.12.0.zip \
    && unzip findsecbugs-cli-1.12.0.zip -d /opt/findsecbugs \
    && rm findsecbugs-cli-1.12.0.zip \
    && mkdir -p /opt/spotbugs-4.7.3/plugin/ \
    && cp /opt/findsecbugs/lib/findsecbugs-plugin-1.12.0.jar /opt/spotbugs-4.7.3/plugin/

RUN mkdir -p /opt/dependency-check \
    && wget -q https://github.com/jeremylong/DependencyCheck/releases/download/v7.4.4/dependency-check-7.4.4-release.zip \
    && unzip dependency-check-7.4.4-release.zip -d /opt \
    && rm dependency-check-7.4.4-release.zip \
    && ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check

RUN pip3 install semgrep

WORKDIR /code

COPY analyze.sh /usr/local/bin/analyze.sh
RUN chmod +x /usr/local/bin/analyze.sh

ENTRYPOINT ["/usr/local/bin/analyze.sh"] 