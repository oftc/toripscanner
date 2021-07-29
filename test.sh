#!/usr/bin/env bash
set -eux
flake8 toripscanner
mypy toripscanner
