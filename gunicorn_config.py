import os

bind = "0.0.0.0:" + os.environ.get("PORT", "10000")
workers = 2
threads = 2
worker_class = "sync"
timeout = 120
max_requests = 1000
max_requests_jitter = 100
preload_app = True