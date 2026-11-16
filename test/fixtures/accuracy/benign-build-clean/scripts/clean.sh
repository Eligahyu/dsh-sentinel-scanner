#!/bin/sh
# Benign build cleanup. Static fixture; never executed by the scanner.
rm -rf ./dist
rm -rf ./node_modules/.cache
rm -rf dist/
rm -rf /tmp/build-cache
rm -rf "$PWD/coverage"
rm -rf ./cache/home/files
