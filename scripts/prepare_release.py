#!/usr/bin/env python3
"""Prepare a tagged atlas-engine build. Does not publish or change Git state."""

import argparse
import datetime
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
import urllib.parse

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
MAX_SBOM_BYTES = 1024 * 1024
MAX_RELEASE_IDENTITY_BYTES = 64 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_SBOM_NODES = 100_000
SOURCE_REPOSITORY = "https://github.com/Arnon-hs/atlas-engine"
ROOT_DESCRIPTION = (
    "Offline, read-only source repository analysis, structural indexing and security scanning"
)
SLSA_STATUS = "No SLSA level claimed; verify hosted attestations and release policy separately."
CYCLONEDX_COMPONENT_TYPES = {"application", "library"}
RELEASE_METADATA_KEYS = {
    "engine_version", "schema_version", "tag", "source_repository",
    "source_revision", "target", "cargo_lock_sha256", "rustc", "workflow",
    "slsa_status",
}
CYCLONEDX_TOP_KEYS = {
    "bomFormat", "specVersion", "version", "serialNumber", "metadata",
    "components", "dependencies",
}
CYCLONEDX_METADATA_KEYS = {"timestamp", "tools", "component", "properties"}
CYCLONEDX_ROOT_KEYS = {
    "type", "bom-ref", "components", "description", "externalReferences",
    "licenses", "name", "purl", "scope", "version",
}
CYCLONEDX_TARGET_KEYS = {"type", "bom-ref", "name", "purl", "version"}
CYCLONEDX_COMPONENT_KEYS = {
    "type", "bom-ref", "description", "externalReferences", "licenses",
    "name", "purl", "scope", "version",
}
CYCLONEDX_COMPONENT_OPTIONAL_KEYS = {"author", "hashes"}


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


def _walk_json(value):
    stack = [value]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > MAX_SBOM_NODES:
            raise ValueError("SBOM node limit exceeded")
        yield current
        if isinstance(current, dict):
            stack.extend(reversed(list(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))


def _decode_purl_piece(raw):
    if (not isinstance(raw, str) or not raw
            or re.search(r"%(?![0-9A-Fa-f]{2})", raw)):
        raise ValueError("invalid Cargo package URL")
    try:
        decoded = urllib.parse.unquote(raw, encoding="utf-8", errors="strict")
    except UnicodeError:
        raise ValueError("invalid Cargo package URL") from None
    # A percent sign after one decode is ambiguous and permits a second parser
    # to reinterpret a file URI or absolute path that this boundary did not see.
    if ("%" in decoded or any(ord(character) < 0x20 or ord(character) == 0x7f
                              for character in decoded)):
        raise ValueError("invalid Cargo package URL")
    return decoded


def _path_or_local_uri(value, *, subpath=False):
    folded = value.casefold()
    if folded.startswith(("file:", "path+file:")):
        return True
    if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    if subpath:
        if "\\" in value:
            return True
        parts = value.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return True
    return False


def _cargo_purl(purl, *, strip_local_download=False):
    """Parse and canonicalize the Cargo PURL subset emitted for this release."""
    if (not isinstance(purl, str) or len(purl) > 4096
            or not purl.startswith("pkg:cargo/")
            or purl.count("#") > 1 or purl.count("?") > 1):
        raise ValueError("invalid Cargo package URL")
    base, fragment_separator, raw_subpath = purl.partition("#")
    package, query_separator, raw_query = base.partition("?")
    identity = package.removeprefix("pkg:cargo/")
    if identity.count("@") != 1 or "/" in identity:
        raise ValueError("invalid Cargo package URL")
    raw_name, raw_version = identity.split("@", 1)
    name = _decode_purl_piece(raw_name)
    version = _decode_purl_piece(raw_version)
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]*", version)):
        raise ValueError("invalid Cargo package URL")

    qualifiers = {}
    seen_qualifier_keys = set()
    if query_separator:
        if not raw_query:
            raise ValueError("invalid Cargo package URL")
        for raw_qualifier in raw_query.split("&"):
            raw_key, separator, raw_value = raw_qualifier.partition("=")
            if not separator:
                raise ValueError("invalid Cargo package URL")
            key = _decode_purl_piece(raw_key).casefold()
            value = _decode_purl_piece(raw_value)
            if (not re.fullmatch(r"[a-z][a-z0-9._-]*", key)
                    or key in seen_qualifier_keys or not value):
                raise ValueError("invalid Cargo package URL")
            seen_qualifier_keys.add(key)
            if key == "download_url" and _path_or_local_uri(value):
                if strip_local_download:
                    continue
                raise ValueError("Cargo package URL contains a local path")
            if _path_or_local_uri(value):
                raise ValueError("Cargo package URL contains a local path")
            qualifiers[key] = value

    subpath = None
    if fragment_separator:
        subpath = _decode_purl_piece(raw_subpath)
        if (_path_or_local_uri(subpath, subpath=True)
                or any(not all(character.isalnum() or character in "-._~"
                                for character in part)
                       for part in subpath.split("/"))):
            raise ValueError("Cargo package URL contains an unsafe subpath")

    canonical = f"pkg:cargo/{name}@{version}"
    if qualifiers:
        canonical += "?" + "&".join(
            f"{key}={urllib.parse.quote(qualifiers[key], safe='-._~')}"
            for key in sorted(qualifiers)
        )
    if subpath is not None:
        canonical += "#" + "/".join(
            urllib.parse.quote(part, safe="-._~") for part in subpath.split("/")
        )
    return {"canonical": canonical, "name": name, "version": version}


def _contains_nonportable_path(value):
    if not isinstance(value, str):
        return False
    candidates = []
    candidate = value
    for _ in range(8):
        if candidate in candidates:
            break
        candidates.append(candidate)
        try:
            decoded = urllib.parse.unquote(candidate, encoding="utf-8", errors="strict")
        except UnicodeError:
            return True
        if decoded == candidate:
            break
        candidate = decoded
    else:
        # Excessive nested encoding is not needed by the generated SBOM and is
        # unsafe to hand to consumers that may decode more times than Atlas.
        return True
    for candidate in candidates:
        folded = candidate.casefold()
        if "path+file:" in folded:
            return True
        if re.search(r"(?i)(?:^|[^a-z0-9+.-])file:", candidate):
            return True
        if re.search(r"\\\\[^\\/]+[\\/]", candidate):
            return True
        if re.search(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]", candidate):
            return True
        for index, character in enumerate(candidate):
            if character != "/":
                continue
            if index == 0:
                return True
            if candidate[index - 1] == "/":
                if (index >= 2 and candidate[index - 2] == ":"
                        and re.fullmatch(
                            r"[A-Za-z][A-Za-z0-9+.-]*", candidate[:index - 2]
                        )):
                    continue
                return True
            if (candidate[index - 1] == ":" and index + 1 < len(candidate)
                    and candidate[index + 1] == "/"
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", candidate[:index - 1])):
                continue
            if not candidate[index - 1].isalnum():
                return True
    return False


def _cyclonedx_components(sbom):
    metadata = sbom.get("metadata")
    components = sbom.get("components")
    if (not isinstance(metadata, dict) or not isinstance(metadata.get("component"), dict)
            or not isinstance(components, list) or not components):
        raise ValueError("SBOM component structure is invalid")
    root = metadata["component"]
    all_components = []
    stack = [root, *reversed(components)]
    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            raise ValueError("SBOM component structure is invalid")
        all_components.append(component)
        nested = component.get("components", [])
        if not isinstance(nested, list):
            raise ValueError("SBOM component structure is invalid")
        stack.extend(reversed(nested))
        if len(all_components) > MAX_SBOM_NODES:
            raise ValueError("SBOM node limit exceeded")
    return root, components, all_components


def _metadata_properties(sbom):
    raw_properties = sbom["metadata"].get("properties", [])
    if not isinstance(raw_properties, list):
        raise ValueError("SBOM metadata properties are invalid")
    properties = {}
    for prop in raw_properties:
        if (not isinstance(prop, dict) or not isinstance(prop.get("name"), str)
                or not prop["name"] or not isinstance(prop.get("value"), str)):
            raise ValueError("SBOM metadata properties are invalid")
        properties.setdefault(prop["name"], []).append(prop["value"])
    return properties


def _validate_licenses(licenses):
    if (not isinstance(licenses, list) or not licenses
            or any(not isinstance(item, dict) or set(item) != {"expression"}
                   or not isinstance(item["expression"], str) or not item["expression"]
                   for item in licenses)):
        raise ValueError("SBOM component licenses are invalid")


def _validate_external_references(references):
    if (not isinstance(references, list) or not references
            or any(not isinstance(item, dict) or set(item) != {"type", "url"}
                   or not isinstance(item["type"], str) or not item["type"]
                   or not isinstance(item["url"], str) or not item["url"]
                   for item in references)):
        raise ValueError("SBOM component external references are invalid")


def _valid_cyclonedx_timestamp(value):
    if not isinstance(value, str):
        return False
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z", value
    )
    if not match:
        return False
    fraction = match.group(2)
    normalized = match.group(1)
    if fraction is not None:
        normalized += "." + fraction[:6].ljust(6, "0")
    try:
        parsed = datetime.datetime.fromisoformat(normalized + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() == datetime.timedelta(0)


def _validate_cyclonedx_05_structure(sbom):
    """Accept only the pinned cargo-cyclonedx 0.5.9 document subset."""
    if not isinstance(sbom, dict) or set(sbom) != CYCLONEDX_TOP_KEYS:
        raise ValueError("unexpected SBOM structure")
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != CYCLONEDX_METADATA_KEYS:
        raise ValueError("unexpected SBOM metadata structure")
    root = metadata.get("component")
    if not isinstance(root, dict) or set(root) != CYCLONEDX_ROOT_KEYS:
        raise ValueError("unexpected SBOM root component structure")
    if (root.get("description") != ROOT_DESCRIPTION
            or root.get("scope") != "required"):
        raise ValueError("SBOM root component fields are invalid")
    _validate_licenses(root.get("licenses"))
    _validate_external_references(root.get("externalReferences"))
    if root["licenses"] != [{"expression": "MIT OR Apache-2.0"}]:
        raise ValueError("SBOM root component license is invalid")
    if root["externalReferences"] != [
        {"type": "website", "url": SOURCE_REPOSITORY},
        {"type": "vcs", "url": SOURCE_REPOSITORY},
    ]:
        raise ValueError("SBOM root component source references are invalid")

    nested = root.get("components")
    if (not isinstance(nested, list) or len(nested) != 1
            or not isinstance(nested[0], dict) or set(nested[0]) != CYCLONEDX_TARGET_KEYS):
        raise ValueError("unexpected SBOM binary target structure")

    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("SBOM component structure is invalid")
    for component in components:
        if (not isinstance(component, dict)
                or not CYCLONEDX_COMPONENT_KEYS.issubset(component)
                or set(component) - CYCLONEDX_COMPONENT_KEYS
                - CYCLONEDX_COMPONENT_OPTIONAL_KEYS):
            raise ValueError("unexpected SBOM component structure")
        if (component.get("type") != "library"
                or not isinstance(component.get("description"), str)
                or not component["description"]
                or component.get("scope") not in {"required", "optional", "excluded"}
                or "author" in component
                and (not isinstance(component["author"], str) or not component["author"])):
            raise ValueError("SBOM component fields are invalid")
        _validate_licenses(component.get("licenses"))
        _validate_external_references(component.get("externalReferences"))
        if "hashes" in component:
            hashes = component["hashes"]
            if (not isinstance(hashes, list) or not hashes
                    or any(not isinstance(item, dict) or set(item) != {"alg", "content"}
                           or item.get("alg") != "SHA-256"
                           or not isinstance(item.get("content"), str)
                           or not re.fullmatch(r"[0-9a-f]{64}", item["content"])
                           or set(item["content"]) == {"0"}
                           for item in hashes)):
                raise ValueError("SBOM component hashes are invalid")

    properties = metadata.get("properties")
    if (not isinstance(properties, list) or not properties
            or any(not isinstance(item, dict) or set(item) != {"name", "value"}
                   or not isinstance(item["name"], str) or not item["name"]
                   or not isinstance(item["value"], str)
                   for item in properties)):
        raise ValueError("SBOM metadata properties are invalid")

    dependencies = sbom.get("dependencies")
    if (not isinstance(dependencies, list) or not dependencies
            or any(not isinstance(item, dict)
                   or set(item) not in ({"ref"}, {"ref", "dependsOn"})
                   for item in dependencies)):
        raise ValueError("unexpected SBOM dependency structure")


def validate_cyclonedx_sbom(sbom, *, expected_version=None, expected_properties=None):
    """Validate portable component identities and the CycloneDX dependency graph."""
    for _item in _walk_json(sbom):
        pass
    _validate_cyclonedx_05_structure(sbom)
    if (not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX"
            or sbom.get("specVersion") != "1.5"
            or type(sbom.get("version")) is not int or sbom["version"] < 1):
        raise ValueError("unexpected SBOM format")
    metadata = sbom.get("metadata")
    if (not isinstance(sbom.get("serialNumber"), str)
            or not re.fullmatch(
                r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                sbom["serialNumber"],
            )
            or not isinstance(metadata, dict)
            or not _valid_cyclonedx_timestamp(metadata.get("timestamp"))
            or metadata.get("tools") != [{
                "vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.9",
            }]):
        raise ValueError("unexpected SBOM generator metadata")

    root, top_components, all_components = _cyclonedx_components(sbom)
    references = set()
    for item in all_components:
        reference = item.get("bom-ref")
        component_type = item.get("type")
        name = item.get("name")
        version = item.get("version")
        purl = item.get("purl")
        if not isinstance(reference, str) or not reference or reference in references:
            raise ValueError("SBOM component references must be unique strings")
        if (component_type not in CYCLONEDX_COMPONENT_TYPES
                or not isinstance(name, str) or not name
                or not isinstance(version, str) or not version):
            raise ValueError("SBOM component identity is invalid")
        parsed = _cargo_purl(purl)
        if parsed["canonical"] != purl or parsed["name"] != name or parsed["version"] != version:
            raise ValueError("SBOM component identity is inconsistent")
        references.add(reference)

    root_version = root.get("version")
    if (root.get("type") != "application" or root.get("name") != "atlas-engine"
            or root.get("scope") != "required"
            or not re.fullmatch(r"\d+\.\d+\.\d+", root_version or "")
            or expected_version is not None and root_version != expected_version):
        raise ValueError("SBOM root component identity is invalid")
    expected_root_ref = f"pkg:cargo/atlas-engine@{root_version}"
    if root.get("bom-ref") != expected_root_ref or root.get("purl") != expected_root_ref:
        raise ValueError("SBOM root component identity is invalid")
    nested_targets = root.get("components")
    expected_target_ref = f"{expected_root_ref}#src/main.rs"
    if (not isinstance(nested_targets, list) or len(nested_targets) != 1
            or nested_targets[0].get("type") != "application"
            or nested_targets[0].get("name") != "atlas-engine"
            or nested_targets[0].get("version") != root_version
            or nested_targets[0].get("bom-ref") != expected_target_ref
            or nested_targets[0].get("purl") != expected_target_ref
            or nested_targets[0].get("components")
            or any(component.get("components") for component in top_components)):
        raise ValueError("SBOM binary target identity is invalid")

    dependencies = sbom.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("SBOM dependencies are invalid")
    dependency_references = set()
    expected_dependency_references = {
        root["bom-ref"], *(component["bom-ref"] for component in top_components)
    }
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("SBOM dependencies are invalid")
        reference = dependency.get("ref")
        depends_on = dependency.get("dependsOn", [])
        if (not isinstance(reference, str) or reference not in references
                or reference in dependency_references or not isinstance(depends_on, list)
                or any(not isinstance(item, str) for item in depends_on)
                or len(depends_on) != len(set(depends_on))
                or any(item not in expected_dependency_references for item in depends_on)):
            raise ValueError("SBOM dependency references are invalid")
        dependency_references.add(reference)

    if dependency_references != expected_dependency_references:
        raise ValueError("SBOM dependency graph does not match its components")

    properties = _metadata_properties(sbom)
    if expected_properties is not None:
        for property_name, expected_value in expected_properties.items():
            if properties.get(property_name) != [expected_value]:
                raise ValueError("SBOM release properties are invalid")

    for value in _walk_json(sbom):
        if isinstance(value, dict):
            if any(_contains_nonportable_path(key) for key in value):
                raise ValueError("SBOM contains a non-portable build-host path")
        elif _contains_nonportable_path(value):
            raise ValueError("SBOM contains a non-portable build-host path")


def sanitize_cyclonedx_sbom(sbom):
    """Replace cargo-cyclonedx local path references with portable package identities."""
    if (not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX"
            or sbom.get("specVersion") != "1.5"
            or type(sbom.get("version")) is not int or sbom["version"] < 1):
        raise ValueError("unexpected SBOM format")
    _root, _top_components, components = _cyclonedx_components(sbom)
    mapping = {}
    portable_references = set()
    rewrites = []
    for item in components:
        reference = item.get("bom-ref")
        if not isinstance(reference, str) or not reference or reference in mapping:
            raise ValueError("SBOM component references must be unique strings")
        local_path_reference = reference.casefold().startswith("path+file:")
        parsed = _cargo_purl(item.get("purl"), strip_local_download=local_path_reference)
        portable = parsed["canonical"] if local_path_reference else reference
        if portable in portable_references:
            raise ValueError("portable SBOM component references collide")
        mapping[reference] = portable
        portable_references.add(portable)
        rewrites.append((item, portable, parsed["canonical"], local_path_reference))

    for item, portable, canonical_purl, local_path_reference in rewrites:
        item["bom-ref"] = portable
        if local_path_reference:
            item["purl"] = canonical_purl

    dependencies = sbom.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("SBOM dependencies are invalid")
    for dependency in dependencies:
        if not isinstance(dependency, dict) or dependency.get("ref") not in mapping:
            raise ValueError("SBOM dependency references are invalid")
        dependency["ref"] = mapping[dependency["ref"]]
        depends_on = dependency.get("dependsOn", [])
        if (not isinstance(depends_on, list)
                or any(not isinstance(item, str) or item not in mapping for item in depends_on)):
            raise ValueError("SBOM dependency references are invalid")
        dependency["dependsOn"] = [mapping[item] for item in depends_on]

    validate_cyclonedx_sbom(sbom)
    return sbom


def _load_cyclonedx_sbom(path, sanitize=False, *, expected_version=None,
                         expected_properties=None):
    if (not path.is_file() or path.is_symlink()
            or path.stat().st_size > MAX_SBOM_BYTES):
        raise ValueError("release SBOM is invalid")
    try:
        sbom = json.loads(
            path.read_bytes(),
            object_pairs_hook=_strict_json_object,
            parse_constant=_invalid_json_constant,
        )
        if sanitize:
            return sanitize_cyclonedx_sbom(sbom)
        validate_cyclonedx_sbom(
            sbom, expected_version=expected_version,
            expected_properties=expected_properties,
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError("release SBOM is invalid") from None
    return sbom


def _release_name_fields(name):
    if not isinstance(name, str):
        raise ValueError("release asset name is invalid")
    for target in TARGETS:
        prefix = "atlas-engine-v"
        suffix = f"-{target}"
        if name.startswith(prefix) and name.endswith(suffix):
            version = name[len(prefix):-len(suffix)]
            tag = f"v{version}"
            if name == release_identity(tag, target, version):
                return version, tag, target
    raise ValueError("release asset name is invalid")


def _load_release_identity(path, name):
    if (not path.is_file() or path.is_symlink()
            or path.stat().st_size > MAX_RELEASE_IDENTITY_BYTES):
        raise ValueError("release identity is invalid")
    try:
        release = json.loads(
            path.read_bytes(),
            object_pairs_hook=_strict_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError("release identity is invalid") from None
    version, tag, target = _release_name_fields(name)
    source_revision = release.get("source_revision") if isinstance(release, dict) else None
    workflow = release.get("workflow") if isinstance(release, dict) else None
    if (not isinstance(release, dict) or set(release) != RELEASE_METADATA_KEYS
            or release.get("engine_version") != version
            or release.get("schema_version") != "1.0"
            or release.get("tag") != tag
            or release.get("source_repository") != SOURCE_REPOSITORY
            or not isinstance(source_revision, str)
            or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source_revision)
            or set(source_revision) == {"0"}
            or release.get("target") != target
            or not isinstance(release.get("cargo_lock_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", release["cargo_lock_sha256"])
            or set(release["cargo_lock_sha256"]) == {"0"}
            or not isinstance(release.get("rustc"), str)
            or not release["rustc"] or len(release["rustc"]) > 256
            or any(character in "\r\n\0" for character in release["rustc"])
            or not (workflow is None or isinstance(workflow, str)
                    and re.fullmatch(
                        r"https://github\.com/Arnon-hs/atlas-engine/actions/runs/[0-9]+",
                        workflow,
                    ))
            or release.get("slsa_status") != SLSA_STATUS):
        raise ValueError("release identity is invalid")
    if any(_contains_nonportable_path(value) for value in _walk_json(release)
           if isinstance(value, str)):
        raise ValueError("release identity contains a non-portable build-host path")
    return release


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
    version, tag, target = _release_name_fields(name)
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

    release = _load_release_identity(assets[f"{name}.release.json"], name)
    expected_properties = {
        "cdx:rustc:sbom:target:triple": target,
        "atlas-engine:source-revision": release["source_revision"],
        "atlas-engine:release-tag": tag,
        "atlas-engine:target": target,
        "atlas-engine:cargo-lock-sha256": release["cargo_lock_sha256"],
    }
    _load_cyclonedx_sbom(
        assets[f"{name}.cdx.json"], expected_version=version,
        expected_properties=expected_properties,
    )

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
                    member_limit = (MAX_SBOM_BYTES if member.name.endswith("/sbom.cdx.json")
                                    else MAX_RELEASE_IDENTITY_BYTES)
                    if member.size > member_limit:
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
        asset_limit = (MAX_SBOM_BYTES if asset_name.endswith(".cdx.json")
                       else MAX_RELEASE_IDENTITY_BYTES)
        if asset.stat().st_size > asset_limit:
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
    sbom = _load_cyclonedx_sbom(sbom_file, sanitize=True)
    sbom.setdefault("metadata", {}).setdefault("properties", []).extend([
        {"name": "atlas-engine:source-revision", "value": sha},
        {"name": "atlas-engine:release-tag", "value": tag},
        {"name": "atlas-engine:target", "value": target},
        {"name": "atlas-engine:cargo-lock-sha256", "value": lock_hash},
    ])
    validate_cyclonedx_sbom(
        sbom, expected_version=version,
        expected_properties={
            "cdx:rustc:sbom:target:triple": target,
            "atlas-engine:source-revision": sha,
            "atlas-engine:release-tag": tag,
            "atlas-engine:target": target,
            "atlas-engine:cargo-lock-sha256": lock_hash,
        },
    )
    epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True))
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    release = {
        "engine_version": version, "schema_version": "1.0", "tag": tag,
        "source_repository": SOURCE_REPOSITORY,
        "source_revision": sha, "target": target, "cargo_lock_sha256": lock_hash,
        "rustc": subprocess.check_output(["rustc", "--version"], cwd=ROOT, text=True).strip(),
        "workflow": ("https://github.com/Arnon-hs/atlas-engine/actions/runs/" + os.environ["GITHUB_RUN_ID"])
                    if os.environ.get("GITHUB_RUN_ID", "").isdigit() else None,
        "slsa_status": SLSA_STATUS,
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
