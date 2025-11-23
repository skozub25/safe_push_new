#!/usr/bin/env bash
set -e  # fail fast if any step fails

echo "Running tests (pytest)..."
pytest

echo "Running SafePush pre-commit scan..."
python3 -m cli.precommit_scan
