#!/usr/bin/env bash
# Diagnostic for the open "strace -u puzzle": does a tracee started with `strace -u sandbox` really
# lose root, and can it truncate the root-owned trace file? Run as root in the sandbox container.
# Prints facts; asserts nothing. Compared against the setpriv drop that tier 4 actually uses.
mkdir -p /diag
cat > /tmp/victim.sh <<'V'
echo "tracee: euid=$(id -u) egid=$(id -g) groups=$(id -G)"
grep -E '^(Uid|Gid|CapPrm|CapEff|CapBnd|NoNewPrivs):' /proc/self/status | tr '\n' ' '; echo
if : > /diag/t.trace 2>/dev/null; then echo "tracee: TRUNCATE SUCCEEDED"; else echo "tracee: truncate refused"; fi
V
report() {
  local f=/diag/t.trace
  echo "  trace owner uid=$(stat -c %u $f) mode=$(stat -c %a $f) size=$(stat -c %s $f) NUL bytes=$(tr -cd '\0' < $f | wc -c)"
  echo "  strace saw execve of: $(grep -c execve $f) call(s)"
}
run() { # run <label> <command...>
  local label="$1"; shift; rm -f /diag/t.trace
  echo "== $label =="; "$@"; report
}
run "root tracee (baseline: expect truncate to succeed)" strace -f -qq -o /diag/t.trace bash /tmp/victim.sh
run "strace -u sandbox"                                   strace -f -qq -o /diag/t.trace -u sandbox bash /tmp/victim.sh
run "setpriv drop (what tier 4 uses)"                     strace -f -qq -o /diag/t.trace setpriv --reuid=sandbox --regid=sandbox --init-groups --reset-env bash /tmp/victim.sh
run "strace -u sandbox, tracee is a script run via env"   strace -f -qq -o /diag/t.trace -u sandbox env bash /tmp/victim.sh
echo "== strace version =="; strace -V | head -1
