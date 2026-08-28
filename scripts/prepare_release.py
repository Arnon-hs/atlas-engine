#!/usr/bin/env python3
"""Prepare a tagged atlas-engine build. Does not publish or change Git state."""

import argparse
import gzip
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

from collect_licenses import ROOT, collect

TARGETS = {
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin", "x86_64-apple-darwin",
}


def release_identity(tag, target, version):
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag) or tag != f"v{version}":
        raise ValueError("tag must equal workspace version as vMAJOR.MINOR.PATCH")
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    return f"atlas-engine-{tag}-{target}"


def source_revision(tag, root):
    """Require one clean, tagged source identity in a trusted engine checkout."""
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("invalid release tag")
    try:
        sha = subprocess.check_output([
            "git", "rev-parse", "--verify", "HEAD^{commit}",
        ], cwd=root, text=True, stderr=subprocess.PIPE).strip()
        tagged_sha = subprocess.check_output([
            "git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}",
        ], cwd=root, text=True, stderr=subprocess.PIPE).strip()
        if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", sha) or tagged_sha != sha:
            raise ValueError("release tag does not identify the checked-out commit")
        subprocess.run([
            "git", "diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--",
        ], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        untracked = subprocess.check_output([
            "git", "ls-files", "--others", "--exclude-standard", "-z",
        ], cwd=root, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise ValueError("release requires an existing tag, commit and clean tracked source") from None
    if untracked:
        raise ValueError("release checkout contains non-ignored untracked files")
    return sha


def main(validate_only=False):
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    tag = os.environ["ATLAS_RELEASE_TAG"]
    target = os.environ["ATLAS_RELEASE_TARGET"]
    name = release_identity(tag, target, version)
    sha = source_revision(tag, ROOT)
    if validate_only:
        print(f"Validated {name} from {sha}")
        return
    binary = ROOT / "target" / target / "release" / "atlas-engine"
    if not binary.is_file() or binary.is_symlink():
        raise ValueError("release binary is missing")
    lock_hash = hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()
    # The previous locked build fetches the dependency graph. Prevent the SBOM
    # tool from accessing the network and verify it leaves Cargo.lock unchanged.
    subprocess.run([
        "cargo", "cyclonedx", "--manifest-path", "crates/atlas-engine-cli/Cargo.toml",
        "--format", "json", "--spec-version", "1.5", "--all", "--all-features",
        "--target", target, "--override-filename", f"{name}.cdx",
    ], cwd=ROOT, env={**os.environ, "CARGO_NET_OFFLINE": "true"}, check=True)
    if hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest() != lock_hash:
        raise ValueError("SBOM generation changed Cargo.lock")
    sbom_file = ROOT / "crates" / "atlas-engine-cli" / f"{name}.cdx.json"
    sbom = json.loads(sbom_file.read_text())
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise ValueError("unexpected SBOM format")
    sbom.setdefault("metadata", {}).setdefault("properties", []).extend([
        {"name": "atlas-engine:source-revision", "value": sha},
        {"name": "atlas-engine:release-tag", "value": tag},
        {"name": "atlas-engine:target", "value": target},
        {"name": "atlas-engine:cargo-lock-sha256", "value": lock_hash},
    ])
    epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True))
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    release = {
        "engine_version": version, "schema_version": "1.0", "tag": tag,
        "source_repository": "https://github.com/Arnon-hs/atlas-engine",
        "source_revision": sha, "target": target, "cargo_lock_sha256": lock_hash,
        "rustc": subprocess.check_output(["rustc", "--version"], cwd=ROOT, text=True).strip(),
        "workflow": ("https://github.com/Arnon-hs/atlas-engine/actions/runs/" + os.environ["GITHUB_RUN_ID"])
                    if os.environ.get("GITHUB_RUN_ID", "").isdigit() else None,
        "slsa_status": "No SLSA level claimed; verify hosted attestations and release policy separately.",
    }
    (output / f"{name}.cdx.json").write_text(json.dumps(sbom, indent=2) + "\n")
    (output / f"{name}.release.json").write_text(json.dumps(release, indent=2) + "\n")
    with tempfile.TemporaryDirectory(prefix="atlas-release-") as temporary:
        package = pathlib.Path(temporary) / name
        package.mkdir()
        shutil.copy2(binary, package / "atlas-engine")
        for filename in ["README.md", "LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE", "CHANGELOG.md"]:
            shutil.copy2(ROOT / filename, package / filename)
        shutil.copytree(ROOT / "schemas", package / "schemas")
        collect(package / "third-party-licenses", target)
        shutil.copy2(output / f"{name}.cdx.json", package / "sbom.cdx.json")
        shutil.copy2(output / f"{name}.release.json", package / "release.json")
        # Normalize archive metadata only. This does not prove byte-for-byte
        # reproducibility of the compiler, linkers, SDKs, or hosted runner.
        def normalize(info):
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            return info
        archive = output / f"{name}.tar.gz"
        with archive.open("wb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as tar:
                    tar.add(package, arcname=name, filter=normalize)
    assets = [output / f"{name}{suffix}" for suffix in [".tar.gz", ".cdx.json", ".release.json"]]
    (output / f"{name}.sha256").write_text("".join(
        f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n" for asset in assets))
    print(f"Prepared {name}; no artifacts published.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true")
    main(parser.parse_args().validate_only)
