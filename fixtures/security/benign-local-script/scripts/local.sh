# SPDX-License-Identifier: Apache-2.0
set -eu
mkdir -p generated
printf '%s\n' "local fixture" > generated/report.txt
printf '%s\n' "$PATH" >> generated/report.txt
