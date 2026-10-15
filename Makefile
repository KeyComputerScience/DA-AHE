.PHONY: install test demo audit manifest environment independent-simulation verify-independent
PYTHON ?= python3
install:
	$(PYTHON) -m pip install -e '.[dev,pq]'
test:
	$(PYTHON) -m pytest -q
demo:
	$(PYTHON) -m daahe demo --output runs/demo
audit:
	$(PYTHON) -m daahe audit --root .
manifest:
	$(PYTHON) -m daahe manifest --root . --output runs/current-source-manifest.json
environment:
	$(PYTHON) tools/capture_environment.py --output runs/environment.json

independent-simulation:
	$(PYTHON) tools/run_simulation_campaign.py --config simulation/config.json --output runs/simulation --jobs 4

verify-independent:
	$(PYTHON) tools/verify_simulation_campaign.py runs/simulation

