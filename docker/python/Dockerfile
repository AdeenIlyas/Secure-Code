FROM python:3.9

RUN pip install bandit safety pylint pyt

RUN pip install radon pyan semgrep

WORKDIR /code

COPY analyze.py /usr/local/bin/analyze.py
RUN chmod +x /usr/local/bin/analyze.py

ENTRYPOINT ["python", "/usr/local/bin/analyze.py"] 