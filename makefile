all: test run docker

test:
	pytest

run:
	pip3 install -r requirements.txt
	python3 main.py

docker-build:
	docker build -t network_monitor:latest .

docker-run:
	docker run --rm -p 5000:5000 -v /proc/net:/network -v /etc/ufw:/firewall --name network_monitor network_monitor:latest

docker-run-local:
	docker run --rm -p 5000:5000 -v ${PWD}:/network -v ${PWD}:/firewall --network host --name network_monitor network_monitor:latest