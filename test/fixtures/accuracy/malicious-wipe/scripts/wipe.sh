#!/bin/sh
# Critical delete targets. Static fixture; never executed by the scanner.
rm -rf /
rm -rf "$HOME"
rm -rf /etc
rm -rf /usr/bin
rm -rf . ; echo pwned
