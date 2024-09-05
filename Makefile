.PHONY: test-python
test-python: install
	python3 test.py

.PHONY: install
docs: install
	sphinx-build -M html docs/source docs/build

.PHONY: install
install:
	cargo build --release
	maturin build
	pip3 install --user --break-system-packages --force-reinstall target/wheels/*.whl

