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
import unicodedata

from collect_licenses import ROOT, collect

TARGETS = {
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin", "x86_64-apple-darwin",
}
TRUSTED_MAIN_REF = "refs/remotes/origin/main"
MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_LICENSE_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_LICENSE_FILE_BYTES = 1024 * 1024
MAX_RELEASE_METADATA_BYTES = 16 * 1024 * 1024
MAX_CHECKSUM_BYTES = 4096


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
        trusted_main_sha = subprocess.check_output([
            "git", "rev-parse", "--verify", f"{TRUSTED_MAIN_REF}^{{commit}}",
        ], cwd=root, text=True, stderr=subprocess.PIPE).strip()
        if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", trusted_main_sha):
            raise ValueError("trusted main ref does not identify a commit")
        subprocess.run([
            "git", "merge-base", "--is-ancestor", tagged_sha, trusted_main_sha,
        ], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        subprocess.run([
            "git", "diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--",
        ], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        untracked = subprocess.check_output([
            "git", "ls-files", "--others", "--exclude-standard", "-z",
        ], cwd=root, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise ValueError(
            "release requires an existing tag, commit, trusted main ancestry and clean tracked source"
        ) from None
    if untracked:
        raise ValueError("release checkout contains non-ignored untracked files")
    return sha


def _strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _invalid_json_constant(_value):
    raise ValueError("invalid JSON numeric constant")


def _canonical_member_name(member_name, package_name):
    if not isinstance(member_name, str) or "\\" in member_name:
        raise ValueError("release archive path is invalid")
    parts = member_name.split("/")
    if (not parts or parts[0] != package_name
            or any(part in {"", ".", ".."} for part in parts)
            or pathlib.PurePosixPath(member_name).is_absolute()
            or pathlib.PurePosixPath(*parts).as_posix() != member_name):
        raise ValueError("release archive path is invalid")
    return parts


def _read_member(package, member, retained_limit=None):
    if retained_limit is not None and member.size > retained_limit:
        raise ValueError("release archive metadata file exceeds its byte limit")
    source = package.extractfile(member)
    if source is None:
        raise ValueError("release archive file could not be read")
    digest = hashlib.sha256()
    retained = bytearray() if retained_limit is not None else None
    read_bytes = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        read_bytes += len(chunk)
        if read_bytes > member.size:
            raise ValueError("release archive file size is invalid")
        digest.update(chunk)
        if retained is not None:
            retained.extend(chunk)
    if read_bytes != member.size:
        raise ValueError("release archive file size is invalid")
    return digest.hexdigest(), bytes(retained) if retained is not None else None


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_license_inventory(raw_inventory, target, actual_files):
    try:
        inventory = json.loads(
            raw_inventory,
            object_pairs_hook=_strict_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("release license inventory is invalid") from None
    expected_keys = {"format_version", "target", "root_package", "components", "limitations"}
    if (not isinstance(inventory, dict) or set(inventory) != expected_keys
            or type(inventory.get("format_version")) is not int
            or inventory.get("format_version") != 1
            or inventory.get("target") != target
            or inventory.get("root_package") != "atlas-engine"
            or not isinstance(inventory.get("limitations"), str)
            or not isinstance(inventory.get("components"), list)
            or not inventory["components"]
            or len(inventory["components"]) > MAX_ARCHIVE_MEMBERS):
        raise ValueError("release license inventory is invalid")

    components = set()
    declared_files = {}
    for component in inventory["components"]:
        if not isinstance(component, dict):
            raise ValueError("release license inventory is invalid")
        name = component.get("name")
        version = component.get("version")
        declared_license = component.get("declared_license")
        license_files = component.get("license_files")
        if (not isinstance(name, str) or not name or len(name) > 256
                or not isinstance(version, str) or not version or len(version) > 256
                or not isinstance(declared_license, str) or not declared_license
                or not isinstance(license_files, list)
                or not 1 <= len(license_files) <= 100
                or (name, version) in components):
            raise ValueError("release license inventory is invalid")
        components.add((name, version))
        component_prefix = f"{name}-{version}/"
        for license_file in license_files:
            if not isinstance(license_file, dict) or set(license_file) != {"path", "sha256"}:
                raise ValueError("release license inventory is invalid")
            path = license_file["path"]
            digest = license_file["sha256"]
            if (not isinstance(path, str) or len(path) > 4096 or "\\" in path
                    or not path.startswith(component_prefix)
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                    or pathlib.PurePosixPath(path).is_absolute()
                    or pathlib.PurePosixPath(path).as_posix() != path
                    or not isinstance(digest, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)
                    or path in declared_files):
                raise ValueError("release license inventory is invalid")
            declared_files[path] = digest

    if set(actual_files) != set(declared_files):
        raise ValueError("release archive license files do not match the inventory")
    if any(actual_files[path] != digest for path, digest in declared_files.items()):
        raise ValueError("release archive license file hash mismatch")


def validate_prepared_assets(output, name):
    """Re-open a prepared binary release and verify its bounded asset set."""
    suffixes = (".tar.gz", ".cdx.json", ".release.json")
    assets = {f"{name}{suffix}": output / f"{name}{suffix}" for suffix in suffixes}
    checksum = output / f"{name}.sha256"
    if any(not path.is_file() or path.is_symlink() for path in [*assets.values(), checksum]):
        raise ValueError("release asset set is incomplete")
    if checksum.stat().st_size > MAX_CHECKSUM_BYTES:
        raise ValueError("release checksum manifest exceeds its byte limit")
    lines = checksum.read_text().splitlines()
    expected_names = set(assets)
    seen = set()
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if not match or match.group(2) not in expected_names or match.group(2) in seen:
            raise ValueError("release checksum manifest is invalid")
        digest, filename = match.groups()
        if _sha256_file(assets[filename]) != digest:
            raise ValueError("release asset checksum mismatch")
        seen.add(filename)
    if seen != expected_names:
        raise ValueError("release checksum manifest is incomplete")

    archive = assets[f"{name}.tar.gz"]
    required = {
        f"{name}/atlas-engine",
        f"{name}/README.md",
        f"{name}/LICENSE",
        f"{name}/LICENSE-MIT",
        f"{name}/LICENSE-APACHE",
        f"{name}/NOTICE",
        f"{name}/CHANGELOG.md",
        f"{name}/schemas/diagnostic-event-v1.schema.json",
        f"{name}/schemas/version-v1.schema.json",
        f"{name}/third-party-licenses/inventory.json",
        f"{name}/sbom.cdx.json",
        f"{name}/release.json",
    }
    names = set()
    aliases = set()
    files = set()
    required_directories = set()
    total = 0
    embedded = {}
    license_files = {}
    inventory = None
    target = next((target for target in TARGETS if name.endswith(f"-{target}")), None)
    if target is None:
        raise ValueError("release archive target is invalid")
    with tarfile.open(archive, mode="r|gz") as package:
        for count, member in enumerate(package, start=1):
            if count > MAX_ARCHIVE_MEMBERS:
                raise ValueError("release archive has too many members")
            parts = _canonical_member_name(member.name, name)
            alias = unicodedata.normalize("NFC", member.name).casefold()
            if member.name in names or alias in aliases:
                raise ValueError("release archive path is invalid")
            names.add(member.name)
            aliases.add(alias)
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise ValueError("release archive contains a link or special file")
            parents = {"/".join(parts[:index]) for index in range(1, len(parts))}
            if (any(parent in files for parent in parents)
                    or member.isfile() and member.name in required_directories
                    or member.isdir() and member.size != 0):
                raise ValueError("release archive path is invalid")
            required_directories.update(parents)
            if member.isfile():
                if member.size < 0:
                    raise ValueError("release archive file size is invalid")
                files.add(member.name)
                total += member.size
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("release archive expansion limit exceeded")
                if member.name == f"{name}/atlas-engine" and member.mode & 0o111 == 0:
                    raise ValueError("release binary is not executable")
                if member.name in {f"{name}/sbom.cdx.json", f"{name}/release.json"}:
                    if member.size > MAX_RELEASE_METADATA_BYTES:
                        raise ValueError("release metadata file exceeds its byte limit")
                    embedded[member.name] = (_read_member(package, member)[0], member.size)
                elif parts[1:2] == ["third-party-licenses"]:
                    relative_name = "/".join(parts[2:])
                    if relative_name == "inventory.json":
                        _, inventory = _read_member(
                            package, member, MAX_LICENSE_INVENTORY_BYTES
                        )
                    else:
                        if member.size > MAX_LICENSE_FILE_BYTES:
                            raise ValueError("release archive license file exceeds its byte limit")
                        license_files[relative_name] = _read_member(package, member)[0]
    if not required.issubset(files):
        raise ValueError("release archive is missing required material")
    if inventory is None:
        raise ValueError("release archive is missing its license inventory")
    _validate_license_inventory(inventory, target, license_files)
    for embedded_name, asset_name, label in [
        (f"{name}/sbom.cdx.json", f"{name}.cdx.json", "SBOM"),
        (f"{name}/release.json", f"{name}.release.json", "release identity"),
    ]:
        asset = assets[asset_name]
        if asset.stat().st_size > MAX_RELEASE_METADATA_BYTES:
            raise ValueError("release metadata file exceeds its byte limit")
        if embedded.get(embedded_name) != (_sha256_file(asset), asset.stat().st_size):
            raise ValueError(f"embedded {label} differs from the release asset")


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
        f"{_sha256_file(asset)}  {asset.name}\n" for asset in assets))
    validate_prepared_assets(output, name)
    print(f"Prepared {name}; no artifacts published.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true")
    main(parser.parse_args().validate_only)
