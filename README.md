# Network Scanner
Scans for new network traffic and reports the results

# Install
Verify Docker is installed and functional.

## Run
There are two ways to run this program. The first is using the makefile commands `make docker-build` and `make docker-run`. The second is to run it manually:
`docker build -t network_monitor:latest .`
`docker rm -f network_monitor`
`docker run -p 5000:5000 -v ${PWD}:/network --name network_monitor network_monitor:latest`

If you want to run this outside of a docker container, you can run:
`pip install -r requirements.txt`
`python3 main.py`

# Test
Run `pip install -U pytest` to install pytest. Then run `make test`.
See `.github/workflows/python-app.yml` for CI testing
