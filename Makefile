test-python:
	cargo build --release
	cp target/release/libpyrtls.dylib ./pyrtls.so
	python3 test.py
