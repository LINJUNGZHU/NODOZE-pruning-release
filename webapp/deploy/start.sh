#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-1}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
exec "${NODOZE_PYTHON:-python}" -m gunicorn -c webapp/deploy/gunicorn.conf.py webapp.backend.app:app
