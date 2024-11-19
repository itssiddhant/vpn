import multiprocessing

# Gunicorn configuration
bind = "0.0.0.0:8000"  # Change this if you want to use a different port
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
worker_class = "gthread"
timeout = 30
keepalive = 2

# Logging
accesslog = "/var/log/gunicorn/access.log"
errorlog = "/var/log/gunicorn/error.log"
loglevel = "info"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190