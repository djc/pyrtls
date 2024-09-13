ssl:
	python3 -m timeit -r 20 -s "import bench_ssl; ctx = bench_ssl.setup()" "bench_ssl.request(ctx)"

pyrtls:
	python3 -m timeit -r 20 -s "import bench_pyrtls; config = bench_pyrtls.setup()" "bench_pyrtls.request(config)"
