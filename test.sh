#!/usr/bin/env bash
set -eux
flake8 toripscanner
mypy --install-types
mypy toripscanner
vulture toripscanner
