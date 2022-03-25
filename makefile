all: test run docker

test:
	pytest

run:
	python3 main.py

docker-build:
	docker build -t network_monitor:latest .

docker-run:
	docker rm -f network_monitor
	docker run -p 5000:5000 -v ${PWD}:/network --name network_monitor network_monitor:latest