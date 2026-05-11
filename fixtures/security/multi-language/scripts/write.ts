// SPDX-License-Identifier: Apache-2.0
import { writeFileSync } from "node:fs";

const token: string | undefined = process.env["SERVICE_TOKEN"];
writeFileSync("../outside.txt", "generated");
