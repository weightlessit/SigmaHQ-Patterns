#!/usr/bin/env python3
"""
Extract detection patterns from SigmaHQ rules for use with
the Post-Infection Persistence Hunter PowerShell script.

Parses targeted rule directories and outputs a single JSON file
containing deduplicated command-line, image/process, and registry patterns.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SIGMA_ROOT = Path("sigma")

TARGET_DIRS = [
    "rules/windows/process_creation",
    "rules/windows/registry/registry_set",
    "rules/windows/registry/registry_add",
    "rules-threat-hunting/windows/process_creation",
]

# Fields we care about and their output categories
FIELD_MAP = {
    "commandline": "CommandPatterns",
    "command_line": "CommandPatterns",
    "image": "ImagePatterns",
    "parentimage": "ImagePatterns",
    "originalfilename": "ImagePatterns",
    "targetobject": "RegistryPatterns",
}

OUTPUT_FILE = "sigma_patterns.json"


def extract_values_from_yaml_lines(lines: list[str]) -> dict[str, list[str]]:
    """
    Extract field values from raw YAML lines without a YAML parser.
    Handles both inline values and list items under a field.
    """
    results: dict[str, list[str]] = {v: [] for v in set(FIELD_MAP.values())}
    current_category = None

    for line in lines:
        stripped = line.rstrip()

        # Check if this line defines a field we care about
        field_match = re.match(r"^\s+([\w]+)\|?\w*:\s*(.*)", stripped)
        if field_match:
            field_name = field_match.group(1).lower()
            value = field_match.group(2).strip().strip("'\"")

            if field_name in FIELD_MAP:
                current_category = FIELD_MAP[field_name]
                if len(value) > 3:
                    results[current_category].append(value)
            else:
                current_category = None
            continue

        # Check if this is a list item under the current field
        list_match = re.match(r"^\s+-\s+(.*)", stripped)
        if list_match and current_category:
            value = list_match.group(1).strip().strip("'\"")
            if len(value) > 3:
                results[current_category].append(value)
            continue

        # Any other non-indented or non-list line resets context
        if stripped and not stripped.startswith(" ") and not stripped.startswith("#"):
            current_category = None

    return results


def process_rules() -> dict:
    """Process all targeted Sigma rule directories."""
    all_patterns: dict[str, set[str]] = {
        "CommandPatterns": set(),
        "ImagePatterns": set(),
        "RegistryPatterns": set(),
    }

    rules_processed = 0
    rules_errored = 0

    for rel_dir in TARGET_DIRS:
        full_dir = SIGMA_ROOT / rel_dir
        if not full_dir.exists():
            print(f"  WARN: Directory not found, skipping — {rel_dir}")
            continue

        for yml_file in full_dir.rglob("*.yml"):
            try:
                lines = yml_file.read_text(encoding="utf-8").splitlines()
                extracted = extract_values_from_yaml_lines(lines)
                rules_processed += 1

                for category, values in extracted.items():
                    all_patterns[category].update(values)
            except Exception as e:
                rules_errored += 1

    # Sort and convert sets to lists for JSON serialization
    output = {
        category: sorted(values) for category, values in all_patterns.items()
    }

    output["_metadata"] = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "rules_processed": rules_processed,
        "rules_errored": rules_errored,
        "command_pattern_count": len(output["CommandPatterns"]),
        "image_pattern_count": len(output["ImagePatterns"]),
        "registry_pattern_count": len(output["RegistryPatterns"]),
    }

    return output


def main():
    print("Extracting Sigma patterns...")

    if not SIGMA_ROOT.exists():
        print(f"ERROR: Sigma directory not found at {SIGMA_ROOT}")
        exit(1)

    output = process_rules()
    meta = output["_metadata"]

    print(f"  Rules processed: {meta['rules_processed']}")
    print(f"  Rules errored:   {meta['rules_errored']}")
    print(f"  Command patterns: {meta['command_pattern_count']}")
    print(f"  Image patterns:   {meta['image_pattern_count']}")
    print(f"  Registry patterns: {meta['registry_pattern_count']}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  Output written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
