.PHONY: test demo

test:
	python -m unittest discover -s tests -v

demo:
	python -m da_ahe.demo

