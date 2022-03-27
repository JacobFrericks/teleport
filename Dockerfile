FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y python3-pip  python3-scapy

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt
RUN pip3 install scapy

COPY . .

CMD [ "python3", "./main.py" ]