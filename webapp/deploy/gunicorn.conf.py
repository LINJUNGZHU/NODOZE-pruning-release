"""One process owns the bounded-memory run cache and investigation lock."""
import os
bind = os.environ.get('NODOZE_BIND', '127.0.0.1:8000')
# Never silently expose an unauthenticated demo through a Gunicorn bind override.
if not bind.startswith(('127.0.0.1:', 'localhost:', '[::1]:', 'unix:')) and not os.environ.get('NODOZE_ACCESS_TOKEN'):
    raise RuntimeError('Non-loopback bind requires NODOZE_ACCESS_TOKEN and NODOZE_SESSION_SECRET')
workers = 1
worker_class = 'gthread'
threads = 4
timeout = 300
graceful_timeout = 60
accesslog = '-'
errorlog = '-'
# Do not log query strings, authentication data or exported event content.
access_log_format = '%(h)s %(m)s %(U)s %(s)s %(L)s'
