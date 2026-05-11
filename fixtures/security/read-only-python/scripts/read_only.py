# SPDX-License-Identifier: Apache-2.0
from pathlib import Path


def read_notes() -> list[str]:
    notes = Path("references/notes.txt")
    if not notes.exists():
        return []
    return notes.read_text(encoding="utf-8").splitlines()


if __name__ == "__main__":
    for line in read_notes():
        print(line)
