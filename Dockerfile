FROM python:3.12

LABEL version="1.1"
LABEL author="0liverFlow"
LABEL description="HookPhish is a Python script designed to aid in the detection of phishing websites"

WORKDIR ./app

COPY . .

RUN pip install -r requirements.txt

ENTRYPOINT ["python3.12", "./HookPhish.py"]
