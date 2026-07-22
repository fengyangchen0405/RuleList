#!/usr/bin/env python3
"""Validate Surge rule list files: syntax, duplicates, conflicts, and redundancy."""

import argparse
import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

# ── Valid rule types ──
VALID_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "GEOIP",
    "URL-REGEX",
    "USER-AGENT",
    "PROCESS-NAME",
    "SRC-PORT",
    "IN-PORT",
    "DEST-PORT",
    "PROTOCOL",
    "SRC-IP",
    "SUBNET",
    "DEVICE-NAME",
    "MAC-ADDRESS",
    "HOSTNAME-TYPE",
    "CELLULAR-RADIO",
    "SCRIPT",
    "AND",
    "OR",
    "NOT",
}

# ── Effective policy represented by each source file ──
POLICY_BY_FILE = {
    "Direct.list": "DIRECT",
    "Proxy.list": "PROXY",
    "AI.list": "AI",
    "JP.list": "JAPAN",
    "Singapore.list": "SINGAPORE",
}

EXPECTED_PROFILE_POLICIES = {
    "Direct.list": "DIRECT",
    "Proxy.list": "🚀 节点选择",
    "AI.list": "🤖 AI",
    "JP.list": "🇯🇵 日本节点",
    "Singapore.list": "🇸🇬 新加坡节点",
}

SURGE_DIR = Path(__file__).resolve().parent.parent / "Surge"


def parse_rules(filepath: Path) -> list[tuple[int, str]]:
    """Parse a .list file and return [(lineno, raw_line)]."""
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
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"  ✗ {fname}:{lineno}  invalid URL-REGEX: {exc}")
                continue
            if pattern.startswith("^") and pattern.endswith("$") and "://" not in pattern:
                errors.append(
                    f"  ✗ {fname}:{lineno}  anchored URL-REGEX must include a URL scheme → {line}"
                )
            continue

        # PROCESS-NAME value can contain paths with special chars
        if line.startswith("PROCESS-NAME,"):
            value = line[len("PROCESS-NAME,"):]
            if not value:
                errors.append(f"  ✗ {fname}:{lineno}  empty PROCESS-NAME value")
            normalized = value.strip('"')
            if normalized.startswith("/Applications/") and normalized.endswith(".app"):
                errors.append(
                    f"  ✗ {fname}:{lineno}  App Bundle path must end with '/' → {line}"
                )
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
        if rule_type in ("SRC-PORT", "IN-PORT", "DEST-PORT"):
            if not re.fullmatch(r"(?:\d+(?:-\d+)?|(?:>=|<=|>|<)\d+)", value):
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


def parse_domain_rule(line: str) -> tuple[str, str] | None:
    rule_type, separator, value = line.partition(",")
    if not separator or rule_type not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        return None
    return rule_type, value.lower()


def domain_rule_covers(broad: tuple[str, str], narrow: tuple[str, str]) -> bool:
    broad_type, broad_value = broad
    narrow_type, narrow_value = narrow
    if broad_type == "DOMAIN-KEYWORD":
        return broad_value in narrow_value
    if broad_type == "DOMAIN-SUFFIX" and narrow_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return narrow_value == broad_value or narrow_value.endswith("." + broad_value)
    return broad_type == narrow_type == "DOMAIN" and broad_value == narrow_value


def check_conflicts(all_rules: dict[str, list[tuple[int, str]]]) -> list[str]:
    """Detect domain rules whose coverage overlaps across different policies."""
    errors = []
    domain_rules = []
    for fname, lines in all_rules.items():
        policy = POLICY_BY_FILE.get(fname, fname)
        for lineno, line in lines:
            parsed = parse_domain_rule(line)
            if parsed:
                domain_rules.append((fname, lineno, policy, line, parsed))

    for index, left in enumerate(domain_rules):
        for right in domain_rules[index + 1:]:
            left_file, left_line, left_policy, left_raw, left_rule = left
            right_file, right_line, right_policy, right_raw, right_rule = right
            if left_policy == right_policy or left_raw.lower() == right_raw.lower():
                continue
            if not (
                domain_rule_covers(left_rule, right_rule)
                or domain_rule_covers(right_rule, left_rule)
            ):
                continue
            errors.append(
                f"  ✗ semantic conflict: {left_file}:{left_line} ({left_policy}) "
                f"'{left_raw}' overlaps {right_file}:{right_line} ({right_policy}) "
                f"'{right_raw}'"
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


def check_profile_references(profile: Path, list_files: list[Path]) -> list[str]:
    errors = []
    references: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for lineno, raw in enumerate(profile.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.lstrip().startswith("RULE-SET,"):
            continue
        fields = next(csv.reader([raw], skipinitialspace=True))
        if len(fields) < 3 or "/RuleList/main/Surge/" not in fields[1]:
            continue
        filename = fields[1].rsplit("/", 1)[-1]
        references[filename].append((lineno, fields[2]))

    for rule_file in list_files:
        entries = references.get(rule_file.name, [])
        if not entries:
            errors.append(f"  ✗ {rule_file.name} is not referenced by profile")
            continue
        expected_policy = EXPECTED_PROFILE_POLICIES.get(rule_file.name)
        if expected_policy is None:
            continue
        for lineno, actual_policy in entries:
            if actual_policy != expected_policy:
                errors.append(
                    f"  ✗ profile:{lineno} {rule_file.name} uses '{actual_policy}', "
                    f"expected '{expected_policy}'"
                )
        if len(entries) > 1:
            errors.append(f"  ✗ {rule_file.name} is referenced multiple times by profile")

    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--surge-dir",
        type=Path,
        default=SURGE_DIR,
        help="directory containing Surge .list files",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        help="optional Surge profile used to verify ruleset references and policies",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    list_files = sorted(args.surge_dir.glob("*.list"))
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
    syntax_errors = [
        f"  ✗ unregistered policy file: {f.name}"
        for f in list_files
        if f.name not in POLICY_BY_FILE
    ]
    for f in list_files:
        syntax_errors.extend(check_syntax(f, all_rules[f.name]))
    if syntax_errors:
        has_error = True
        print("\n".join(syntax_errors))
    else:
        print("  ✓ All rules have valid syntax")

    if args.profile:
        print("\n── Profile Integration Check ──")
        if not args.profile.is_file():
            profile_errors = [f"  ✗ profile not found: {args.profile}"]
        else:
            profile_errors = check_profile_references(args.profile, list_files)
        if profile_errors:
            has_error = True
            print("\n".join(profile_errors))
        else:
            print("  ✓ All rule lists are referenced with the expected policy")

    # 2. Duplicates
    print("\n── Duplicate Check ──")
    dup_errors = check_duplicates(all_rules)
    if dup_errors:
        has_error = True
        print("\n".join(dup_errors))
    else:
        print("  ✓ No duplicates found")

    # 3. Conflicts
    print("\n── Conflict Check (Cross-policy Semantics) ──")
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
