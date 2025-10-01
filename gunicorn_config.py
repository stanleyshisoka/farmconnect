import multiprocessing

bind = "0.0.0.0:10000"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
worker_class = "eventlet"
timeout = 120
max_requests = 1000
max_requests_jitter = 100