all: test run docker

test:
	pytest

run:
    pip install -r requirements.txt
	python3 main.py

docker-build:
	docker build -t network_monitor:latest .

docker-run:
	docker rm -f network_monitor
	docker run -p 5000:5000 -v /proc/net:/network --name network_monitor network_monitor:latest

docker-run-local:
	docker rm -f network_monitor
	docker run -p 5000:5000 -v ${PWD}:/network --privileged --net=host --name network_monitor network_monitor:latest