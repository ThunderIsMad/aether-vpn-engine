#!/usr/bin/env python3
"""Validate the Freebuff skills under .agents/skills/.

Per skill, checks that:
  * the directory name is lowercase/digits/hyphens and equals frontmatter `name`
  * `name` is unique across skills
  * SKILL.md exists, opens and closes its frontmatter with `---`, parses as YAML
  * `description` is a non-empty string within the length limit
  * references to project docs resolve on disk under whitelisted roots only
    (no `..`, no absolute paths, no ROOT-wide `**/` scans), and a bare
    `NN-name.md` reference carries the `design/` prefix (the regression that
    broke the first scaffold run)

Exits non-zero when there are errors; warnings are reported but do not fail.
"""

from __future__ import annotations

import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: python3 -m pip install pyyaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / ".agents" / "skills"
NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
MAX_DESCRIPTION = 1024

# `design/*.md` / `research/*.md` are inputs the skill reads and must exist.
# A bare `NN-name.md` must not appear: it resolves only by luck.
DOC_REF_RE = re.compile(
    r"(?<![\w/-])(?:(?P<prefixed>(?:design|research)/[\w./*-]+\.md)|(?P<bare>\d{2}-[\w-]+\.md))"
)

# Refs from SKILL.md are untrusted input (audit, Low: check_refs/DOC_REF_RE):
# glob-паттерн из SKILL.md не должен сканировать произвольные поддеревья ROOT
# и не должен быть DoS-вектором в CI. Корни — whitelist, `..`/абсолютные — reject,
# число рефов и объём glob-сканирования ограничены.
ALLOWED_DOC_ROOTS = ("design", "research")
MAX_REFS_PER_SKILL = 64
MAX_GLOB_MATCHES = 256


def split_frontmatter(text: str, errors: list[str]) -> tuple[dict | None, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        errors.append("first line must be '---'")
        return None, text
    try:
        end = lines.index("---", 1)
    except ValueError:
        errors.append("frontmatter is never closed by '---'")
        return None, text
    try:
        data = yaml.safe_load("\n".join(lines[1:end]))
    except yaml.YAMLError as exc:
        errors.append(f"frontmatter is not valid YAML: {exc}")
        return None, ""
    if not isinstance(data, dict):
        errors.append("frontmatter must be a YAML mapping")
        return None, ""
    return data, "\n".join(lines[end + 1 :])


def check_refs(text: str, errors: list[str]) -> None:
    """Doc-рефы резолвятся только под whitelisted-корнями внутри ROOT."""
    matches = list(DOC_REF_RE.finditer(text))
    if len(matches) > MAX_REFS_PER_SKILL:
        errors.append(
            f"too many doc references ({len(matches)} > {MAX_REFS_PER_SKILL})"
        )
        return
    for match in matches:
        bare = match.group("bare")
        if bare:
            errors.append(f"bare doc reference {bare!r} — add the design/ prefix")
            continue
        ref = match.group("prefixed")
        parts = pathlib.PurePosixPath(ref).parts
        if not parts or pathlib.PurePosixPath(ref).is_absolute() or ".." in parts:
            errors.append(f"doc reference {ref!r} must be relative and stay inside ROOT")
            continue
        if parts[0] not in ALLOWED_DOC_ROOTS:
            errors.append(
                f"doc reference {ref!r} must start with one of {ALLOWED_DOC_ROOTS}"
            )
            continue
        if len(parts) > 1 and parts[1] == "**":
            errors.append(f"doc reference {ref!r} must not scan ROOT wholesale ('**/' first)")
            continue
        # Ранний break: glob-сканирование ограничено капой (glob-DoS в CI).
        hits = 0
        for _ in ROOT.glob(ref):
            hits += 1
            if hits > MAX_GLOB_MATCHES:
                break
        if hits == 0:
            errors.append(f"doc reference {ref!r} matches no file")
        elif hits > MAX_GLOB_MATCHES:
            errors.append(
                f"doc reference {ref!r} matches too many files (> {MAX_GLOB_MATCHES})"
            )


def check_skill(
    directory: pathlib.Path, errors: list[str], warnings: list[str]
) -> tuple[str, bool, bool]:
    """Return (name, name_is_valid, frontmatter_loaded)."""
    name = directory.name
    valid = bool(NAME_RE.match(name))
    if not valid:
        errors.append(f"directory {name!r} is not lowercase/digits/hyphens")

    skill = directory / "SKILL.md"
    if not skill.is_file():
        errors.append(f"{name}: SKILL.md is missing")
        return name, valid, False

    text = skill.read_text(encoding="utf-8")
    data, body = split_frontmatter(text, errors)
    if data is None:
        return name, valid, False

    fm_name = data.get("name")
    if not isinstance(fm_name, str) or not NAME_RE.match(fm_name):
        errors.append(f"{name}: frontmatter `name` {fm_name!r} is not a valid skill name")
    elif fm_name != name:
        errors.append(f"{name}: frontmatter `name` {fm_name!r} != directory name")

    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        errors.append(f"{name}: `description` must be a non-empty string")
    elif len(description) > MAX_DESCRIPTION:
        errors.append(
            f"{name}: `description` is {len(description)} chars, limit {MAX_DESCRIPTION}"
        )

    if not body.strip():
        warnings.append(f"{name}: body is empty")
    metadata = data.get("metadata")
    if not isinstance(metadata, dict) or not metadata.get("category"):
        warnings.append(f"{name}: `metadata.category` is missing")

    check_refs(text, errors)
    return name, valid, True


def main() -> int:
    if not SKILLS_DIR.is_dir():
        sys.exit(f"no skills directory at {SKILLS_DIR}")

    errors: list[str] = []
    warnings: list[str] = []
    rows: list[tuple[pathlib.Path, str, bool, bool, int]] = []

    for directory in sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir()):
        before = len(errors)
        name, valid, loaded = check_skill(directory, errors, warnings)
        rows.append((directory, name, valid, loaded, len(errors) - before))

    for name in sorted({name for _, name, _, _, _ in rows}):
        if sum(1 for _, other, _, _, _ in rows if other == name) > 1:
            errors.append(f"duplicate skill name {name!r}")

    print(f"{'path':<50}{'name':<24}{'name valid':<12}status")
    print("-" * 96)
    for directory, name, valid, loaded, new_errors in rows:
        status = "OK" if (valid and loaded and new_errors == 0) else "FAIL"
        print(
            f"{directory.relative_to(ROOT).as_posix():<50}{name:<24}{str(valid):<12}{status}"
        )

    print(
        f"\n{len(rows)} skill(s), {len(errors)} error(s), {len(warnings)} warning(s)"
    )
    for message in warnings:
        print(f"  warning: {message}")
    for message in errors:
        print(f"  error:   {message}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
