# SPDX-License-Identifier: Apache-2.0
set -eu
payload=$(printf 'ZWNobyBvawo=' | base64 -d)
eval "$payload"
