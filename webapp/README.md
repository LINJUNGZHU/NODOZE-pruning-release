# PS-RDP Web Demo

This remote-friendly Flask application displays the pre-pruning and
post-pruning THEIA Case 3 graph with certified attack paths. The browser uses a
small representative subgraph; headline metrics always come from the complete
1,132,218-edge score ledger.

Prepare the fast visualization cache once:

```bash
cd /root/NODOZE-pruning-release
PYTHONPATH=. python webapp/scripts/prepare_demo.py
```

Run the service on the remote server:

```bash
cd /root/NODOZE-pruning-release
PYTHONPATH=. python webapp/backend/app.py
```

Forward it from a local computer:

```bash
ssh -N -L 8000:127.0.0.1:8000 root@SERVER_IP
```

Then open `http://127.0.0.1:8000`. Do not expose the Flask development server
directly to the public Internet; use Gunicorn and Nginx for a public deployment.
