# Network Scanner
Scans for new network traffic and reports the results

# Install
Verify Docker is installed and functional.

For running locally, this was tested on Debian. Verify tcpdump and python3-scapy are installed: `sudo apt-get install tcpdump python3-scapy`

## Run
There are two ways to run this program. The first is using the makefile commands `make docker-build` and `make docker-run`. The second is to run it manually:

`docker build -t network_monitor:latest .`

`docker run --rm -p 5000:5000 -v ${PWD}:/firewall --network host --name network_monitor network_monitor:latest`

If you want to run this outside of a docker container, you can run:
`pip install -r requirements.txt`
`python3 main.py`
Or simply run `make run`

Don't forget to consistently update your firewall by running `make reload-firewall` otherwise the new firewall rules will not take effect!

If the program gets in a bad state, or if you want to start over with recording IPs, simply run `make clean`.

# Test
Run `pip install -U pytest` to install pytest. Then run `make test`.
See `.github/workflows/python-app.yml` for CI testing.
