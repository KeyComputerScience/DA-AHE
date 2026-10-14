.PHONY: install test demo audit manifest environment
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
	$(PYTHON) -m daahe manifest --root . --output manifest.json
environment:
	$(PYTHON) tools/capture_environment.py --output runs/environment.json

