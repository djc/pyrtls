test-python:
	cargo build --release
	pip3 install --force-reinstall target/wheels/*.whl
	python3 test.py
