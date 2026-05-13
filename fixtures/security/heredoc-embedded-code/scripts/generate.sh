# SPDX-License-Identifier: Apache-2.0
set -eu

mkdir -p generated

cat > generated/snippet.js <<'JS'
const positive = values => values.filter((value) => value > 0);
const ordered = (left, right) => left >= right;
JS

cat <<'PY' > generated/snippet.py
def positive(value):
    return value > 0 and value >= 1
PY

echo "done" > generated/status.txt
rm -rf generated/cache
