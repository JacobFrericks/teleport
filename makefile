all: test run docker

test:
	pytest

run:
	pip3 install -r requirements.txt
	python3 main.py

reload-firewall:
	./reload_ufw.sh &

clean:
	echo "{}" > './recorded_addrs_file.json'
	/bin/cp -rf ./user.rules_orig ./user.rules

docker-build:
	docker build -t network_monitor:latest .

docker-run:
	docker run --rm -p 5000:5000 -v /etc/ufw:/firewall --name network_monitor network_monitor:latest

docker-run-local:
	docker run --rm -p 5000:5000 -v ${PWD}:/firewall --network host --name network_monitor network_monitor:latest