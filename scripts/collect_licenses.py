#!/usr/bin/env python3
"""Collect exact license/notice files from this project's locked Cargo sources.

Run only in the trusted atlas-engine build checkout, never in a scanned repository.
This is a conservative runtime + build dependency inventory, not legal advice.
"""

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOTICE_NAME = re.compile(r"^(?:licen[sc]e|copying|copyright|notice)(?:[._-].*)?$", re.I)


def collect(destination, target=None):
    command = ["cargo", "metadata", "--locked", "--format-version", "1", "--all-features"]
    if target:
        command += ["--filter-platform", target]
    metadata = json.loads(subprocess.check_output(command, cwd=ROOT))
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    cli = next(package for package in packages.values() if package["name"] == "atlas-engine")
    selected, pending = set(), [cli["id"]]
    while pending:
        package_id = pending.pop()
        if package_id in selected:
            continue
        selected.add(package_id)
        for dep in nodes[package_id]["deps"]:
            if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]):
                pending.append(dep["pkg"])

    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    checksums = {(p["name"], p["version"], p.get("source")): p.get("checksum")
                 for p in lock["package"]}
    overrides = {(item["name"], item["version"]): item for item in
                 json.loads((ROOT / "third-party" / "license-overrides.json").read_text())}
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for package in sorted((packages[key] for key in selected), key=lambda p: (p["name"], p["version"])):
        if package["source"] is None:
            continue  # Own crates are covered by the top-level license files.
        if not package.get("license") and not package.get("license_file"):
            raise ValueError(f"missing license metadata for {package['name']}")
        package_root = pathlib.Path(package["manifest_path"]).parent
        candidates = {p for p in package_root.rglob("*") if NOTICE_NAME.fullmatch(p.name)
                      and p.is_file() and not p.is_symlink()}
        explicit = package.get("license_file")
        if explicit:
            candidate = (package_root / explicit).resolve()
            if not candidate.is_relative_to(package_root.resolve()):
                raise ValueError("license file escapes dependency source")
            candidates.add(candidate)
        origin = "Unmodified files included in the locked Cargo package."
        if not candidates:
            override = overrides.get((package["name"], package["version"]))
            checksum = checksums.get((package["name"], package["version"], package["source"]))
            if not override or checksum != override["cargo_checksum"]:
                raise ValueError(f"no upstream license text found for {package['name']}")
            vcs = json.loads((package_root / ".cargo_vcs_info.json").read_text())
            if vcs["git"]["sha1"] != override["source_revision"]:
                raise ValueError("upstream license revision mismatch")
            candidate = (ROOT / override["license_path"]).resolve()
            if not candidate.is_relative_to((ROOT / "third-party" / "licenses").resolve()):
                raise ValueError("license override escapes reviewed directory")
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != override["license_sha256"]:
                raise ValueError("upstream license text hash mismatch")
            candidates = {candidate}
            package_root = candidate.parent
            origin = override
        if len(candidates) > 100:
            raise ValueError("too many license files; manual review needed")
        crate_directory = destination / f"{package['name']}-{package['version']}"
        texts = []
        for candidate in sorted(candidates):
            if candidate.stat().st_size > 1024 * 1024:
                raise ValueError("oversize license file; manual review needed")
            relative = candidate.relative_to(package_root)
            target_file = crate_directory / relative
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, target_file)
            texts.append({"path": str(target_file.relative_to(destination)),
                          "sha256": hashlib.sha256(target_file.read_bytes()).hexdigest()})
        records.append({
            "name": package["name"], "version": package["version"],
            "source": package["source"], "upstream_repository": package.get("repository"),
            "declared_license": package.get("license"),
            "cargo_checksum": checksums.get((package["name"], package["version"], package["source"])),
            "scope": "runtime_or_build_dependency",
            "modifications": "No source changes made by this collector; Cargo cache integrity is assumed.",
            "license_files": texts,
            "license_origin": origin,
        })
    inventory = {"format_version": 1, "target": target,
                 "root_package": "atlas-engine", "components": records,
                 "limitations": "Excludes toolchain, OS libraries, CI tools, dev-only dependencies and copied material not declared to Cargo; review separately."}
    (destination / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    return inventory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=pathlib.Path)
    parser.add_argument("--target")
    args = parser.parse_args()
    result = collect(args.destination, args.target)
    print(f"Collected upstream notices for {len(result['components'])} dependencies.")
