#!/usr/bin/env python3
"""Install exact upstream cargo-cyclonedx source with a reviewed dependency lock.

This is trusted build tooling, never part of an untrusted repository scan.
"""

import argparse
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / "tools" / "cargo-cyclonedx"


def main(install_root):
    specification = json.loads((POLICY / "source.json").read_text())
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    lock = (POLICY / "Cargo.lock").read_bytes()
    if hashlib.sha256(lock).hexdigest() != specification["lock_sha256"]:
        raise ValueError("reviewed SBOM tool lock hash mismatch")
    # Fail before source execution if advisories or warnings have appeared.
    subprocess.run(["cargo", "audit", "--file", str(POLICY / "Cargo.lock"), "--deny", "warnings"], check=True)
    with urllib.request.urlopen(specification["archive_url"], timeout=30) as response:
        archive = response.read(4 * 1024 * 1024 + 1)
    if len(archive) > 4 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != specification["archive_sha256"]:
        raise ValueError("upstream SBOM tool archive hash mismatch")
    prefix = f"{specification['package']}-{specification['version']}"
    with tempfile.TemporaryDirectory(prefix="atlas-sbom-source-") as temporary:
        temporary = pathlib.Path(temporary)
        total = 0
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            members = tar.getmembers()
            if len(members) > 1000:
                raise ValueError("unexpected SBOM source archive size")
            for member in members:
                relative = pathlib.PurePosixPath(member.name)
                if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != prefix:
                    raise ValueError("SBOM source path escapes archive root")
                destination = temporary.joinpath(*relative.parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    total += member.size
                    if total > 16 * 1024 * 1024:
                        raise ValueError("SBOM source expansion limit")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as source, destination.open("xb") as output:
                        shutil.copyfileobj(source, output)
                else:
                    raise ValueError("unexpected link or special file in SBOM source")
        source_root = temporary / prefix
        vcs = json.loads((source_root / ".cargo_vcs_info.json").read_text())
        if vcs["git"]["sha1"] != specification["upstream_vcs_revision"] or vcs["path_in_vcs"] != specification["path_in_vcs"]:
            raise ValueError("SBOM source revision does not match approved package")
        (source_root / "Cargo.lock").write_bytes(lock)
        build_environment = dict(os.environ)
        build_environment["PATH"] = str(install_root / "bin") + os.pathsep + build_environment.get("PATH", "")
        subprocess.run([
            "cargo", f"+{toolchain}", "install", "--locked", "--path", str(source_root), "--root", str(install_root),
        ], check=True, env=build_environment)
        if (source_root / "Cargo.lock").read_bytes() != lock:
            raise ValueError("SBOM tool installation changed the reviewed lock")
    print(f"Installed reviewed cargo-cyclonedx {specification['version']} into the requested tool root.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    main(parser.parse_args().root.resolve())
