#!/usr/bin/env python3
"""Validate Surge rule list files: syntax, duplicates, conflicts, and redundancy."""

import sys
import re
from pathlib import Path
from collections import defaultdict

# ── Valid rule types ──
VALID_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "URL-REGEX",
    "PROCESS-NAME",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "DEST-PORT",
    "PROTOCOL",
    "SRC-IP",
}

# ── Which files are "direct" vs "proxy" ──
DIRECT_FILES = {"Direct.list"}
PROXY_FILES = {"Proxy.list", "AI.list", "JP.list", "Exit.list"}

SURGE_DIR = Path(__file__).resolve().parent.parent / "Surge"


def parse_rules(filepath: Path) -> list[tuple[int, str, str, str]]:
    """Parse a .list file and return [(lineno, rule_type, value, raw_line)]."""
    rules = []
    for lineno, raw in enumerate(filepath.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rules.append((lineno, line))
    return rules


def check_syntax(filepath: Path, lines: list[tuple[int, str]]) -> list[str]:
    """Check each rule has valid TYPE,value format."""
    errors = []
    fname = filepath.name
    for lineno, line in lines:
        # URL-REGEX can contain commas in the pattern
        if line.startswith("URL-REGEX,"):
            pattern = line[len("URL-REGEX,"):]
            if not pattern:
                errors.append(f"  ✗ {fname}:{lineno}  empty URL-REGEX pattern")
            continue

        # PROCESS-NAME value can contain paths with special chars
        if line.startswith("PROCESS-NAME,"):
            value = line[len("PROCESS-NAME,"):]
            if not value:
                errors.append(f"  ✗ {fname}:{lineno}  empty PROCESS-NAME value")
            continue

        # General format: TYPE,value
        if "," not in line:
            errors.append(f"  ✗ {fname}:{lineno}  missing comma → {line}")
            continue

        parts = line.split(",", 1)
        rule_type, value = parts[0], parts[1]

        if rule_type not in VALID_TYPES:
            errors.append(f"  ✗ {fname}:{lineno}  unknown type '{rule_type}' → {line}")
            continue

        if not value or value != value.strip():
            errors.append(f"  ✗ {fname}:{lineno}  empty or has extra spaces → {line}")
            continue

        # Port rules: value should be numeric
        if rule_type in ("DST-PORT", "SRC-PORT", "IN-PORT", "DEST-PORT"):
            if not re.match(r"^\d+(-\d+)?$", value):
                errors.append(f"  ✗ {fname}:{lineno}  invalid port '{value}'")

        # DOMAIN / DOMAIN-SUFFIX: no wildcard, no protocol
        if rule_type in ("DOMAIN", "DOMAIN-SUFFIX"):
            if value.startswith("*.") or "://" in value:
                errors.append(f"  ✗ {fname}:{lineno}  invalid domain '{value}'")

    return errors


def check_duplicates(all_rules: dict[str, list[tuple[int, str]]]) -> list[str]:
    """Detect exact duplicate rules within and across files."""
    errors = []
    seen: dict[str, list[str]] = defaultdict(list)  # normalized_rule → [file:line, ...]

    for fname, lines in all_rules.items():
        for lineno, line in lines:
            key = line.strip().lower()
            seen[key].append(f"{fname}:{lineno}")

    for rule, locations in seen.items():
        if len(locations) > 1:
            errors.append(f"  ✗ duplicate '{rule}' → {', '.join(locations)}")

    return errors


def check_conflicts(all_rules: dict[str, list[tuple[int, str]]]) -> list[str]:
    """Detect same domain appearing in both Direct and Proxy groups."""
    errors = []

    direct_rules: dict[str, str] = {}   # normalized → file:line
    proxy_rules: dict[str, str] = {}

    for fname, lines in all_rules.items():
        target = direct_rules if fname in DIRECT_FILES else proxy_rules
        for lineno, line in lines:
            key = line.strip().lower()
            target[key] = f"{fname}:{lineno}"

    # Exact match conflicts
    for rule in direct_rules:
        if rule in proxy_rules:
            errors.append(
                f"  ✗ conflict: '{rule}' in Direct ({direct_rules[rule]}) "
                f"AND Proxy ({proxy_rules[rule]})"
            )

    return errors


def check_redundancy(all_rules: dict[str, list[tuple[int, str]]]) -> list[str]:
    """Detect rules that are redundant due to broader rules in the SAME file.

    - DOMAIN-KEYWORD,X  covers  DOMAIN-SUFFIX,*.X.*  and  DOMAIN,*.X.*
    - DOMAIN-SUFFIX,X   covers  DOMAIN,sub.X
    """
    warnings = []

    for fname, lines in all_rules.items():
        keywords = []
        suffixes = []
        domains = []

        for lineno, line in lines:
            if line.startswith("DOMAIN-KEYWORD,"):
                keywords.append((lineno, line.split(",", 1)[1].lower()))
            elif line.startswith("DOMAIN-SUFFIX,"):
                suffixes.append((lineno, line.split(",", 1)[1].lower()))
            elif line.startswith("DOMAIN,"):
                domains.append((lineno, line.split(",", 1)[1].lower()))

        # DOMAIN-KEYWORD covers DOMAIN-SUFFIX and DOMAIN
        for kw_lineno, kw_val in keywords:
            for sf_lineno, sf_val in suffixes:
                if kw_val in sf_val:
                    warnings.append(
                        f"  ⚠ {fname}:{sf_lineno}  DOMAIN-SUFFIX,{sf_val} "
                        f"is covered by DOMAIN-KEYWORD,{kw_val} (line {kw_lineno})"
                    )
            for d_lineno, d_val in domains:
                if kw_val in d_val:
                    warnings.append(
                        f"  ⚠ {fname}:{d_lineno}  DOMAIN,{d_val} "
                        f"is covered by DOMAIN-KEYWORD,{kw_val} (line {kw_lineno})"
                    )

        # DOMAIN-SUFFIX covers DOMAIN
        for sf_lineno, sf_val in suffixes:
            for d_lineno, d_val in domains:
                if d_val == sf_val or d_val.endswith("." + sf_val):
                    warnings.append(
                        f"  ⚠ {fname}:{d_lineno}  DOMAIN,{d_val} "
                        f"is covered by DOMAIN-SUFFIX,{sf_val} (line {sf_lineno})"
                    )

    return warnings


def main():
    list_files = sorted(SURGE_DIR.glob("*.list"))
    if not list_files:
        print("No .list files found in Surge/")
        sys.exit(1)

    all_rules: dict[str, list[tuple[int, str]]] = {}
    for f in list_files:
        all_rules[f.name] = parse_rules(f)

    total_rules = sum(len(v) for v in all_rules.values())
    print(f"📋 Found {len(list_files)} files, {total_rules} rules total\n")

    has_error = False

    # 1. Syntax
    print("── Syntax Check ──")
    syntax_errors = []
    for f in list_files:
        syntax_errors.extend(check_syntax(f, all_rules[f.name]))
    if syntax_errors:
        has_error = True
        print("\n".join(syntax_errors))
    else:
        print("  ✓ All rules have valid syntax")

    # 2. Duplicates
    print("\n── Duplicate Check ──")
    dup_errors = check_duplicates(all_rules)
    if dup_errors:
        has_error = True
        print("\n".join(dup_errors))
    else:
        print("  ✓ No duplicates found")

    # 3. Conflicts
    print("\n── Conflict Check (Direct vs Proxy) ──")
    conflict_errors = check_conflicts(all_rules)
    if conflict_errors:
        has_error = True
        print("\n".join(conflict_errors))
    else:
        print("  ✓ No conflicts found")

    # 4. Redundancy
    print("\n── Redundancy Check ──")
    redundancy_warnings = check_redundancy(all_rules)
    if redundancy_warnings:
        print("\n".join(redundancy_warnings))
    else:
        print("  ✓ No redundant rules found")

    print()
    if has_error:
        print("❌ Validation failed")
        sys.exit(1)
    else:
        print("✅ All checks passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
