all: test run docker

test:
	pytest

run:
<<<<<<< HEAD
	pip install -r requirements.txt
=======
    pip install -r requirements.txt
>>>>>>> main
	python3 main.py

docker-build:
	docker build -t network_monitor:latest .

docker-run:
<<<<<<< HEAD
	docker run --rm -p 5000:5000 -v /proc/net:/network -v /etc/ufw:/firewall --name network_monitor network_monitor:latest

docker-run-local:
	docker run --rm -p 5000:5000 -v ${PWD}:/network -v ${PWD}:/firewall --name network_monitor network_monitor:latest
=======
	docker rm -f network_monitor
	docker run -p 5000:5000 -v /proc/net:/network --name network_monitor network_monitor:latest

docker-run-local:
	docker rm -f network_monitor
	docker run -p 5000:5000 -v ${PWD}:/network --privileged --net=host --name network_monitor network_monitor:latest
>>>>>>> main
