#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

const { main } = require("../lib/agent-audit");

main(process.argv.slice(2), process.env, process.argv[1]);
