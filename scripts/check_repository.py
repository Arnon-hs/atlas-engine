#!/usr/bin/env python3
"""Check local docs, licensing and workflow invariants, not hosted enforcement."""

import hashlib
import json
import pathlib
import re
import sys
import tomllib
from urllib.parse import unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]


def check():
    errors = []
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    if manifest["workspace"]["package"]["license"] != "MIT OR Apache-2.0":
        errors.append("workspace SPDX expression differs from approved license")
    for member in manifest["workspace"]["members"]:
        directory = ROOT / member
        package = tomllib.loads((directory / "Cargo.toml").read_text())["package"]
        if package.get("readme") != "../../README.md":
            errors.append(f"{member}: shared README is not declared")
        if package.get("license") != {"workspace": True}:
            errors.append(f"{member}: license must inherit workspace SPDX")
        for name in ["LICENSE", "LICENSE-MIT", "LICENSE-APACHE"]:
            copy = directory / name
            if not copy.is_file() or copy.is_symlink() or copy.read_bytes() != (ROOT / name).read_bytes():
                errors.append(f"{member}/{name}: missing or stale canonical ordinary-file copy")

    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text()
        if not re.search(r"^permissions:\n  contents: read\n", text, re.M):
            errors.append(f"{workflow.name}: missing workflow read-only default")
        if re.search(r"^\s+pull_request_target:", text, re.M):
            errors.append(f"{workflow.name}: privileged PR event is forbidden")
        for action in re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", text, re.M):
            if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}", action):
                errors.append(f"{workflow.name}: Action is not pinned by full SHA")
        if re.search(r"^\s+persist-credentials:\s*true", text, re.M):
            errors.append(f"{workflow.name}: persisted checkout credentials are forbidden")

    documents = [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md"),
                 *(ROOT / "examples").rglob("README.md"), *(ROOT / "fuzz").glob("*.md"),
                 *(ROOT / "schemas").rglob("*.md"), *(ROOT / "third-party").rglob("*.md")]
    for document in documents:
        text = document.read_text()
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\n]+)\)", text):
            target = target.split(' "', 1)[0].strip('<>')
            parts = urlsplit(target)
            if parts.scheme or not parts.path:
                continue
            referenced = (document.parent / unquote(parts.path)).resolve()
            if not referenced.is_relative_to(ROOT) or not referenced.exists():
                errors.append(f"{document.relative_to(ROOT)}: broken/escaping local link {target}")

    for schema in (ROOT / "schemas").rglob("*.json"):
        try:
            json.loads(schema.read_text())
        except (ValueError, UnicodeError):
            errors.append(f"{schema.relative_to(ROOT)}: invalid JSON")
    expected_sarif = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
    if hashlib.sha256((ROOT / "schemas/vendor/sarif-schema-2.1.0.json").read_bytes()).hexdigest() != expected_sarif:
        errors.append("vendored official SARIF schema hash drift")
    for name in ["OASIS-NOTICES.txt", "OASIS-LICENSE.md"]:
        if not (ROOT / "schemas/vendor" / name).is_file():
            errors.append(f"missing OASIS distribution terms: {name}")
    source = json.loads((ROOT / "tools/cargo-cyclonedx/source.json").read_text())
    if hashlib.sha256((ROOT / "tools/cargo-cyclonedx/Cargo.lock").read_bytes()).hexdigest() != source["lock_sha256"]:
        errors.append("reviewed SBOM tool lock hash drift")
    for override in json.loads((ROOT / "third-party/license-overrides.json").read_text()):
        if hashlib.sha256((ROOT / override["license_path"]).read_bytes()).hexdigest() != override["license_sha256"]:
            errors.append("third-party upstream license hash drift")
    return errors


if __name__ == "__main__":
    problems = check()
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        raise SystemExit(1)
    print("Local documentation links, license copies, Action pins and source identities checked.")
    print("This does not verify hosted CI, remote settings, legal clearance or a published release.")
