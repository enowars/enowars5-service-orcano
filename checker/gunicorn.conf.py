# This is a configuration file required by the checker.
import multiprocessing
worker_class = "gevent"
workers = multiprocessing.cpu_count() * 2 + 1
bind = "0.0.0.0:3031"
timeout = 90
keepalive = 3600
max_requests = 100
preload_app = True
max_requests_jitter = 30