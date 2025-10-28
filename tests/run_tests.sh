#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$REPO_ROOT/tests/mocks:$PATH"
export HOME="$REPO_ROOT/tests/tmp_home"
mkdir -p "$HOME"

test_output="$HOME/test_run.log"
rm -f "$test_output"

printf '1\n4\n192.168.1.1\nn\nno\n' | bash "$REPO_ROOT/SNMPAT.sh" >"$test_output"

if grep -q "SNMPAT completed" "$test_output"; then
    echo "SNMPAT smoke test passed"
    rm -f "$test_output" "$HOME"/SNMPAT_log_*.log
else
    echo "SNMPAT smoke test failed: completion message missing" >&2
    exit 1
fi
