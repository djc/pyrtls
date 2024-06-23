test-python:
	cargo build --release
	maturin build
	pip3 install --user --break-system-packages --force-reinstall target/wheels/*.whl
	python3 test.py

docs:
	sphinx-build -M html docs/source docs/build
