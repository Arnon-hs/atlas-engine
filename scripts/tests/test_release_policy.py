import copy
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import tarfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from check_sast import blocking_findings
from prepare_release import (MAX_SBOM_BYTES, _load_cyclonedx_sbom,
                             main as prepare_release, release_identity,
                             sanitize_cyclonedx_sbom, source_revision,
                             validate_cyclonedx_sbom, validate_prepared_assets)


def sarif_report():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": "high", "properties": {"security-severity": "7.0"}},
            {"id": "low", "properties": {"security-severity": "3.0"}},
            {"id": "unspecified", "defaultConfiguration": {"level": "error"}},
        ]}},
        "invocations": [{"executionSuccessful": True}],
        "results": [],
    }]}


def finding(rule_id, **properties):
    return {"ruleId": rule_id, "message": {"text": "Synthetic test finding"}, **properties}


RELEASE_VERSION = "0.4.2"
RELEASE_TAG = f"v{RELEASE_VERSION}"
RELEASE_TARGET = "aarch64-apple-darwin"
RELEASE_NAME = f"atlas-engine-{RELEASE_TAG}-{RELEASE_TARGET}"
SOURCE_REVISION = "a" * 40
LOCK_SHA256 = "b" * 64
LICENSE_PATH = "synthetic-1.0.0/LICENSE"
LICENSE_TEXT = b"Synthetic MIT license text.\n"


def add_regular_member(package, name, contents=b"adversarial member\n"):
    member = tarfile.TarInfo(name)
    member.mode = 0o644
    member.size = len(contents)
    package.addfile(member, io.BytesIO(contents))


def cargo_sbom(workspace="/home/runner/work/atlas-engine/atlas-engine",
               version=RELEASE_VERSION):
    root_ref = f"path+file://{workspace}/crates/atlas-engine-cli#atlas-engine@{version}"
    library_ref = f"path+file://{workspace}/crates/repo-core#atlas-repo-core@{version}"
    registry_ref = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229"
    registry_purl = "pkg:cargo/serde@1.0.229"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:12345678-1234-4234-8234-123456789abc",
        "metadata": {
            "timestamp": "2026-08-29T00:00:00Z",
            "tools": [{
                "vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.9",
            }],
            "properties": [{
                "name": "cdx:rustc:sbom:target:triple", "value": RELEASE_TARGET,
            }],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "description": (
                    "Offline, read-only source repository analysis, structural indexing "
                    "and security scanning"
                ),
                "externalReferences": [
                    {
                        "type": "website",
                        "url": "https://github.com/Arnon-hs/atlas-engine",
                    },
                    {
                        "type": "vcs",
                        "url": "https://github.com/Arnon-hs/atlas-engine",
                    },
                ],
                "licenses": [{"expression": "MIT OR Apache-2.0"}],
                "name": "atlas-engine",
                "version": version,
                "scope": "required",
                "purl": f"pkg:cargo/atlas-engine@{version}?download_url=file://.",
                "components": [{
                    "type": "application",
                    "bom-ref": root_ref + " bin-target-0",
                    "name": "atlas-engine",
                    "version": version,
                    "purl": (
                        f"pkg:cargo/atlas-engine@{version}"
                        "?download_url=file://.#src/main.rs"
                    ),
                }],
            },
        },
        "components": [{
            "type": "library",
            "bom-ref": library_ref,
            "description": "Synthetic workspace library",
            "externalReferences": [{
                "type": "vcs", "url": "https://github.com/Arnon-hs/atlas-engine",
            }],
            "licenses": [{"expression": "MIT OR Apache-2.0"}],
            "name": "atlas-repo-core",
            "scope": "required",
            "version": version,
            "purl": f"pkg:cargo/atlas-repo-core@{version}?download_url=file://../repo-core",
        }, {
            "type": "library",
            "bom-ref": registry_ref,
            "description": "Synthetic registry library",
            "externalReferences": [{
                "type": "vcs", "url": "https://github.com/serde-rs/serde",
            }],
            "licenses": [{"expression": "MIT OR Apache-2.0"}],
            "name": "serde",
            "scope": "required",
            "version": "1.0.229",
            "purl": registry_purl,
        }],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [library_ref, registry_ref]},
            {"ref": library_ref, "dependsOn": [registry_ref]},
            {"ref": registry_ref, "dependsOn": []},
        ],
    }


def release_sbom():
    sbom = sanitize_cyclonedx_sbom(cargo_sbom())
    sbom["metadata"]["properties"] = [
        {"name": "cdx:rustc:sbom:target:triple", "value": RELEASE_TARGET},
        {"name": "atlas-engine:source-revision", "value": SOURCE_REVISION},
        {"name": "atlas-engine:release-tag", "value": RELEASE_TAG},
        {"name": "atlas-engine:target", "value": RELEASE_TARGET},
        {"name": "atlas-engine:cargo-lock-sha256", "value": LOCK_SHA256},
        {"name": "synthetic:unrelated", "value": "preserved"},
    ]
    return sbom


def release_identity_document():
    return {
        "engine_version": RELEASE_VERSION,
        "schema_version": "1.0",
        "tag": RELEASE_TAG,
        "source_repository": "https://github.com/Arnon-hs/atlas-engine",
        "source_revision": SOURCE_REVISION,
        "target": RELEASE_TARGET,
        "cargo_lock_sha256": LOCK_SHA256,
        "rustc": "rustc 1.98.0 (synthetic)",
        "workflow": None,
        "slsa_status": (
            "No SLSA level claimed; verify hosted attestations and release policy separately."
        ),
    }


def prepared_assets(output, *, extra_member=None, include_license=True,
                    actual_license=LICENSE_TEXT, declared_license=LICENSE_TEXT,
                    required_directory=None, sbom_document=None,
                    release_document=None):
    name = RELEASE_NAME
    package_root = output / name
    for relative in [
        "README.md", "LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE",
        "CHANGELOG.md", "schemas/diagnostic-event-v1.schema.json",
        "schemas/version-v1.schema.json",
    ]:
        path = package_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"synthetic {relative}\n")
    binary = package_root / "atlas-engine"
    binary.write_text("synthetic binary\n")
    binary.chmod(0o755)
    if required_directory is not None:
        path = package_root / required_directory
        path.unlink()
        path.mkdir()

    licenses = package_root / "third-party-licenses"
    licenses.mkdir()
    if include_license:
        license_file = licenses / LICENSE_PATH
        license_file.parent.mkdir()
        license_file.write_bytes(actual_license)
    inventory = {
        "format_version": 1,
        "target": RELEASE_TARGET,
        "root_package": "atlas-engine",
        "components": [{
            "name": "synthetic",
            "version": "1.0.0",
            "source": "registry+https://example.invalid/index",
            "upstream_repository": None,
            "declared_license": "MIT",
            "cargo_checksum": "a" * 64,
            "scope": "runtime_or_build_dependency",
            "modifications": "No source changes.",
            "license_files": [{
                "path": LICENSE_PATH,
                "sha256": hashlib.sha256(declared_license).hexdigest(),
            }],
            "license_origin": "Synthetic fixture.",
        }],
        "limitations": "Synthetic fixture.",
    }
    (licenses / "inventory.json").write_text(json.dumps(inventory) + "\n")

    sbom = output / f"{name}.cdx.json"
    release = output / f"{name}.release.json"
    if sbom_document is None:
        sbom_document = release_sbom()
    if release_document is None:
        release_document = release_identity_document()
    sbom.write_text(json.dumps(sbom_document) + "\n")
    release.write_text(json.dumps(release_document) + "\n")
    (package_root / "sbom.cdx.json").write_bytes(sbom.read_bytes())
    (package_root / "release.json").write_bytes(release.read_bytes())

    archive = output / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        package.add(package_root, arcname=name)
        if extra_member is not None:
            extra_member(package, name)
    assets = [archive, sbom, release]
    (output / f"{name}.sha256").write_text("".join(
        f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n"
        for asset in assets
    ))
    return name


class ReleasePolicyTests(unittest.TestCase):
    def test_sbom_sanitizer_replaces_linux_and_macos_local_refs_consistently(self):
        for workspace in [
            "/home/runner/work/atlas-engine/atlas-engine",
            "/Users/runner/work/atlas-engine/atlas-engine",
        ]:
            with self.subTest(workspace=workspace):
                sbom = cargo_sbom(workspace)
                registry_purl = sbom["components"][1]["purl"]
                sanitized = sanitize_cyclonedx_sbom(sbom)
                root_ref = f"pkg:cargo/atlas-engine@{RELEASE_VERSION}"
                library_ref = f"pkg:cargo/atlas-repo-core@{RELEASE_VERSION}"
                registry_ref = (
                    "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229"
                )

                self.assertEqual(sanitized["metadata"]["component"]["bom-ref"], root_ref)
                self.assertEqual(
                    sanitized["metadata"]["component"]["components"][0]["bom-ref"],
                    root_ref + "#src/main.rs",
                )
                self.assertEqual(sanitized["components"][0]["bom-ref"], library_ref)
                self.assertEqual(sanitized["components"][1]["bom-ref"], registry_ref)
                self.assertEqual(sanitized["components"][1]["purl"], registry_purl)
                self.assertEqual(sanitized["dependencies"], [
                    {"ref": root_ref, "dependsOn": [library_ref, registry_ref]},
                    {"ref": library_ref, "dependsOn": [registry_ref]},
                    {"ref": registry_ref, "dependsOn": []},
                ])
                self.assertNotIn(workspace, json.dumps(sanitized))
                self.assertNotIn("download_url=file", json.dumps(sanitized))
                validate_cyclonedx_sbom(sanitized)

    def test_sbom_sanitizer_rejects_dangling_duplicate_and_colliding_refs(self):
        dangling = cargo_sbom()
        dangling["dependencies"][0]["dependsOn"].append("missing-component")
        duplicate = cargo_sbom()
        duplicate["components"].append(copy.deepcopy(duplicate["components"][1]))
        collision = cargo_sbom()
        colliding = copy.deepcopy(collision["components"][0])
        colliding["bom-ref"] = (
            f"path+file:///different/checkout/repo-core#atlas-repo-core@{RELEASE_VERSION}"
        )
        collision["components"].append(colliding)

        for sbom, message in [
            (dangling, "dependency references"),
            (duplicate, "unique strings"),
            (collision, "references collide"),
        ]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                sanitize_cyclonedx_sbom(sbom)

    def test_sbom_sanitizer_canonicalizes_safe_qualifiers_and_relative_subpath(self):
        sbom = cargo_sbom()
        component = sbom["components"][0]
        component["purl"] = (
            f"pkg:cargo/atlas-repo-core@{RELEASE_VERSION}"
            "?zeta=safe&download_url=file://../repo-core&arch=aarch64#vendor/source.rs"
        )
        sanitized = sanitize_cyclonedx_sbom(sbom)
        canonical = (
            f"pkg:cargo/atlas-repo-core@{RELEASE_VERSION}"
            "?arch=aarch64&zeta=safe#vendor/source.rs"
        )
        self.assertEqual(sanitized["components"][0]["bom-ref"], canonical)
        self.assertEqual(sanitized["components"][0]["purl"], canonical)
        validate_cyclonedx_sbom(sanitized, expected_version=RELEASE_VERSION)

    def test_sbom_purl_rejects_encoded_paths_dot_segments_and_double_encoding(self):
        unsafe_suffixes = [
            "#%2FUsers/runner/work",
            "#C%3A/Users/runner/work",
            "#%5C%5Crunner-host%5Cwork",
            "#src/%2e%2e/secrets",
            "#%252FUsers%252Frunner",
            "?download_url=%2566ile%253A%252F%252F%252Fhome%252Frunner",
            "?download_url=%2570ath%252bfile%253A%252F%252F%252Fhome",
        ]
        for suffix in unsafe_suffixes:
            with self.subTest(suffix=suffix):
                sbom = release_sbom()
                component = sbom["components"][1]
                component["purl"] = f"pkg:cargo/serde@1.0.229{suffix}"
                with self.assertRaisesRegex(ValueError, "Cargo package URL|unsafe subpath"):
                    validate_cyclonedx_sbom(sbom, expected_version=RELEASE_VERSION)

    def test_sbom_validation_rejects_absolute_paths_in_all_string_fields(self):
        leaks = [
            "/",
            "/home/runner/work/atlas-engine",
            "//runner-host/work/atlas-engine",
            "/Users/runner/work/atlas-engine",
            r"C:\Users\runner\work\atlas-engine",
            r"\\runner-host\work\atlas-engine",
            "file:///home/runner/work/atlas-engine",
            "pkg:cargo/example@1.0.0?download_url=file://.",
            "pkg:cargo/example@1.0.0?download_url=file%3A%2F%2F%2FUsers%2Frunner",
        ]
        for leak in leaks:
            with self.subTest(leak=leak):
                sbom = sanitize_cyclonedx_sbom(cargo_sbom())
                sbom["metadata"]["properties"] = [{"name": "host", "value": leak}]
                with self.assertRaisesRegex(ValueError, "build-host path"):
                    validate_cyclonedx_sbom(sbom)

    def test_sbom_validation_bounds_deep_and_wide_json_without_recursion(self):
        deep = "bounded"
        for _ in range(2_000):
            deep = [deep]
        baseline = sanitize_cyclonedx_sbom(cargo_sbom())
        with mock.patch("prepare_release.MAX_SBOM_NODES", 128):
            validate_cyclonedx_sbom(baseline)
        for shape, extra in [("deep", deep), ("wide", list(range(128)))]:
            with self.subTest(shape=shape):
                sbom = sanitize_cyclonedx_sbom(cargo_sbom())
                sbom["metadata"]["extra"] = extra
                with mock.patch("prepare_release.MAX_SBOM_NODES", 128), \
                        self.assertRaisesRegex(ValueError, "node limit"):
                    validate_cyclonedx_sbom(sbom)

    def test_sbom_file_size_is_rejected_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "oversized.cdx.json"
            path.write_bytes(b" " * (MAX_SBOM_BYTES + 1))
            with mock.patch("prepare_release.json.loads") as loader, \
                    self.assertRaisesRegex(ValueError, "release SBOM is invalid"):
                _load_cyclonedx_sbom(path)
            loader.assert_not_called()

    def test_prepared_archive_rejects_sbom_path_leak_even_when_checksums_match(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            sbom = sanitize_cyclonedx_sbom(cargo_sbom())
            sbom["metadata"]["properties"] = [{
                "name": "build-directory", "value": "/Users/runner/work/atlas-engine",
            }]
            name = prepared_assets(output, sbom_document=sbom)
            with self.assertRaisesRegex(ValueError, "release SBOM is invalid"):
                validate_prepared_assets(output, name)

    def test_prepared_assets_reject_prefixed_absolute_paths_with_matching_checksums(self):
        leaks = [
            "prefix[/Users/runner/work/atlas-engine]",
            "urn:build:/home/runner/work/atlas-engine",
            r"prefix[C:\Users\runner\work\atlas-engine]",
        ]
        for leak in leaks:
            with self.subTest(leak=leak), tempfile.TemporaryDirectory() as directory:
                sbom = release_sbom()
                sbom["metadata"]["properties"].append({"name": "host", "value": leak})
                output = pathlib.Path(directory)
                name = prepared_assets(output, sbom_document=sbom)
                with self.assertRaisesRegex(ValueError, "release SBOM is invalid"):
                    validate_prepared_assets(output, name)

    def test_prepared_assets_reject_malformed_or_incomplete_sbom_with_matching_checksums(self):
        cases = []

        encoded_absolute = release_sbom()
        encoded_absolute["components"][1]["purl"] = (
            "pkg:cargo/serde@1.0.229#%2Fhome/runner/work"
        )
        cases.append(("encoded absolute PURL subpath", encoded_absolute))

        double_encoded = release_sbom()
        double_encoded["components"][1]["purl"] = (
            "pkg:cargo/serde@1.0.229"
            "?download_url=%2566ile%253A%252F%252F%252Fhome%252Frunner"
        )
        cases.append(("double encoded file URI", double_encoded))

        cases.append(("header only", {"bomFormat": "CycloneDX", "specVersion": "1.5"}))

        missing_type = release_sbom()
        del missing_type["components"][0]["type"]
        cases.append(("missing component type", missing_type))

        missing_name = release_sbom()
        del missing_name["components"][0]["name"]
        cases.append(("missing component name", missing_name))

        stale_root = release_sbom()
        stale_root["metadata"]["component"]["version"] = "0.4.1"
        cases.append(("stale root version", stale_root))

        wrong_root = release_sbom()
        root = wrong_root["metadata"]["component"]
        root["name"] = "not-atlas-engine"
        root["purl"] = f"pkg:cargo/not-atlas-engine@{RELEASE_VERSION}"
        root["bom-ref"] = root["purl"]
        wrong_root["dependencies"][0]["ref"] = root["bom-ref"]
        cases.append(("wrong root identity", wrong_root))

        empty_components = release_sbom()
        empty_components["components"] = []
        cases.append(("empty components", empty_components))

        empty_dependencies = release_sbom()
        empty_dependencies["dependencies"] = []
        cases.append(("empty dependencies", empty_dependencies))

        missing_root_dependency = release_sbom()
        missing_root_dependency["dependencies"] = missing_root_dependency["dependencies"][1:]
        cases.append(("missing root dependency", missing_root_dependency))

        nested_dependency = release_sbom()
        nested_dependency["dependencies"][0]["dependsOn"].append(
            f"pkg:cargo/atlas-engine@{RELEASE_VERSION}#src/main.rs"
        )
        cases.append(("nested binary target in dependency graph", nested_dependency))

        nested_component = release_sbom()
        nested_component["metadata"]["component"]["components"][0]["components"] = [
            copy.deepcopy(nested_component["components"][1])
        ]
        cases.append(("component nested under binary target", nested_component))

        for label, sbom in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory)
                name = prepared_assets(output, sbom_document=sbom)
                with self.assertRaisesRegex(ValueError, "release SBOM is invalid"):
                    validate_prepared_assets(output, name)

    def test_prepared_assets_reject_non_cyclonedx_05_shapes_with_matching_checksums(self):
        cases = []

        metadata_authors = release_sbom()
        metadata_authors["metadata"]["authors"] = "unexpected string"
        cases.append(("metadata authors string", metadata_authors))

        top_services = release_sbom()
        top_services["services"] = "unexpected string"
        cases.append(("top services string", top_services))

        licenses_string = release_sbom()
        licenses_string["components"][0]["licenses"] = "MIT"
        cases.append(("component licenses string", licenses_string))

        external_references_string = release_sbom()
        external_references_string["components"][0]["externalReferences"] = (
            "https://example.invalid"
        )
        cases.append(("external references string", external_references_string))

        unknown_top_object = release_sbom()
        unknown_top_object["unexpected"] = {"nested": "object"}
        cases.append(("unknown top object", unknown_top_object))

        for label, sbom in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory)
                name = prepared_assets(output, sbom_document=sbom)
                with self.assertRaisesRegex(ValueError, "release SBOM is invalid"):
                    validate_prepared_assets(output, name)

    def test_prepared_assets_bind_project_owned_root_metadata_and_real_timestamp(self):
        cases = []

        gpl_license = release_sbom()
        gpl_license["metadata"]["component"]["licenses"] = [{"expression": "GPL-3.0"}]
        cases.append(("wrong root license", gpl_license))

        wrong_sources = release_sbom()
        wrong_sources["metadata"]["component"]["externalReferences"] = [
            {"type": "website", "url": "https://example.invalid"},
            {"type": "vcs", "url": "https://example.invalid"},
        ]
        cases.append(("wrong root external references", wrong_sources))

        zero_hash = release_sbom()
        zero_hash["components"][0]["hashes"] = [{
            "alg": "SHA-256", "content": "0" * 64,
        }]
        cases.append(("zero component hash", zero_hash))

        invalid_timestamp = release_sbom()
        invalid_timestamp["metadata"]["timestamp"] = "9999-99-99T99:99:99Z"
        cases.append(("invalid UTC timestamp", invalid_timestamp))

        wrong_description = release_sbom()
        wrong_description["metadata"]["component"]["description"] = "Wrong project"
        cases.append(("wrong root description", wrong_description))

        for label, sbom in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory)
                name = prepared_assets(output, sbom_document=sbom)
                with self.assertRaisesRegex(ValueError, "release SBOM is invalid"):
                    validate_prepared_assets(output, name)

    def test_prepared_assets_reject_release_identity_mismatches_with_matching_checksums(self):
        mutations = {
            "version": ("engine_version", "0.4.1"),
            "tag": ("tag", "v0.4.1"),
            "target": ("target", "x86_64-apple-darwin"),
            "source repository": ("source_repository", "https://example.invalid/repo"),
            "source revision": ("source_revision", "c" * 40),
            "build path": ("rustc", "prefix[/Users/runner/toolchain/rustc]"),
        }
        for label, (key, value) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                release = release_identity_document()
                release[key] = value
                output = pathlib.Path(directory)
                name = prepared_assets(output, release_document=release)
                with self.assertRaisesRegex(ValueError, "release identity|release SBOM"):
                    validate_prepared_assets(output, name)

        with tempfile.TemporaryDirectory() as directory:
            release = release_identity_document()
            release["unexpected"] = "not allowed"
            output = pathlib.Path(directory)
            name = prepared_assets(output, release_document=release)
            with self.assertRaisesRegex(ValueError, "release identity is invalid"):
                validate_prepared_assets(output, name)

    def test_prepared_assets_reject_all_zero_resealed_identities(self):
        cases = [
            ("source_revision", "atlas-engine:source-revision", "0" * 40),
            ("cargo_lock_sha256", "atlas-engine:cargo-lock-sha256", "0" * 64),
        ]
        for release_key, property_name, zero_value in cases:
            with self.subTest(release_key=release_key), tempfile.TemporaryDirectory() as directory:
                release = release_identity_document()
                release[release_key] = zero_value
                sbom = release_sbom()
                for prop in sbom["metadata"]["properties"]:
                    if prop["name"] == property_name:
                        prop["value"] = zero_value
                        break
                else:
                    self.fail(f"missing synthetic property {property_name}")
                output = pathlib.Path(directory)
                name = prepared_assets(
                    output, sbom_document=sbom, release_document=release,
                )
                with self.assertRaisesRegex(ValueError, "release identity is invalid"):
                    validate_prepared_assets(output, name)

    def test_prepared_assets_require_reserved_sbom_properties_exactly_once(self):
        for label, mutate in [
            ("missing", lambda props: props.pop(1)),
            ("duplicate", lambda props: props.append(copy.deepcopy(props[1]))),
            ("wrong", lambda props: props[2].update(value="v9.9.9")),
        ]:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                sbom = release_sbom()
                mutate(sbom["metadata"]["properties"])
                output = pathlib.Path(directory)
                name = prepared_assets(output, sbom_document=sbom)
                with self.assertRaisesRegex(ValueError, "release SBOM is invalid"):
                    validate_prepared_assets(output, name)

    def test_prepared_archive_rehearsal_verifies_members_and_sidecars(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            name = prepared_assets(output)
            validate_prepared_assets(output, name)
            (output / f"{name}.cdx.json").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                validate_prepared_assets(output, name)

    def test_prepared_archive_rejects_path_aliases_and_duplicates(self):
        invalid_members = [
            f"{RELEASE_NAME}/./README.md",
            f"{RELEASE_NAME}/nested/../README.md",
            f"{RELEASE_NAME}//README.md",
            f"{RELEASE_NAME}/README.md",
            f"{RELEASE_NAME}/readme.md",
        ]
        for member_name in invalid_members:
            with self.subTest(member_name=member_name), tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory)

                def add_invalid(package, _name):
                    add_regular_member(package, member_name)

                name = prepared_assets(output, extra_member=add_invalid)
                with self.assertRaisesRegex(ValueError, "path is invalid"):
                    validate_prepared_assets(output, name)

    def test_prepared_archive_rejects_links_and_special_files(self):
        for member_type in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE]:
            with self.subTest(member_type=member_type), tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory)

                def add_invalid(package, name):
                    member = tarfile.TarInfo(f"{name}/adversarial")
                    member.type = member_type
                    member.linkname = f"{name}/README.md"
                    package.addfile(member)

                name = prepared_assets(output, extra_member=add_invalid)
                with self.assertRaisesRegex(ValueError, "link or special file"):
                    validate_prepared_assets(output, name)

    def test_prepared_archive_rejects_excessive_expansion(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            name = prepared_assets(output)
            with mock.patch("prepare_release.MAX_ARCHIVE_BYTES", 8), self.assertRaisesRegex(
                ValueError, "expansion limit"
            ):
                validate_prepared_assets(output, name)

    def test_prepared_archive_requires_every_declared_license_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            name = prepared_assets(output, include_license=False)
            with self.assertRaisesRegex(ValueError, "license files do not match"):
                validate_prepared_assets(output, name)

    def test_prepared_archive_requires_regular_required_material(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            name = prepared_assets(output, required_directory="NOTICE")
            with self.assertRaisesRegex(ValueError, "missing required material"):
                validate_prepared_assets(output, name)

    def test_prepared_archive_rejects_corrupt_license_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            name = prepared_assets(output, actual_license=b"corrupt license\n")
            with self.assertRaisesRegex(ValueError, "license file hash mismatch"):
                validate_prepared_assets(output, name)

    def test_prepared_archive_bounds_license_inventory_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            name = prepared_assets(output)
            with mock.patch("prepare_release.MAX_LICENSE_INVENTORY_BYTES", 8), \
                    self.assertRaisesRegex(ValueError, "metadata file exceeds"):
                validate_prepared_assets(output, name)

    def test_identity_requires_exact_version_and_target(self):
        self.assertEqual(release_identity("v0.1.0", "aarch64-apple-darwin", "0.1.0"),
                         "atlas-engine-v0.1.0-aarch64-apple-darwin")
        for tag in ["v0.2.0", "v0.1.0;echo injected", "v0.1.0$(id)", "../v0.1.0", "v0.1.0\n"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_identity(tag, "aarch64-apple-darwin", "0.1.0")
        with self.assertRaises(ValueError):
            release_identity("v0.1.0", "../target", "0.1.0")

    def test_sast_threshold_blocks_high_but_handles_reviewed_suppression(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = pathlib.Path(directory) / "rust.sarif"
            report = sarif_report()
            report["runs"][0]["results"] = [
                finding("high"), finding("low"),
                finding("high", suppressions=[{"kind": "external", "status": "accepted"}]),
                finding("unspecified"),
            ]
            filename.write_text(json.dumps(report))
            self.assertEqual(blocking_findings(directory), 2)
            filename.unlink()
            with self.assertRaises(ValueError):
                blocking_findings(directory)

    def test_sast_requires_real_runs_results_and_valid_critical_structure(self):
        baseline = sarif_report()
        malformed = [[], {}, {"version": "2.1.0", "runs": []},
                     {"version": "2.1.0", "runs": {}}, {"version": "2.1.0", "runs": [None]}]
        for key, value in [("results", None), ("results", {}), ("results", [None]),
                           ("results", [{}]), ("tool", None), ("invocations", {})]:
            report = copy.deepcopy(baseline)
            report["runs"][0][key] = value
            malformed.append(report)
        metadata_only = copy.deepcopy(baseline)
        del metadata_only["runs"][0]["results"]
        malformed.append(metadata_only)
        for driver in [{}, {"name": "CodeQL", "rules": {}},
                       {"name": "CodeQL", "rules": [{"id": "duplicate"}, {"id": "duplicate"}]}]:
            report = copy.deepcopy(baseline)
            report["runs"][0]["tool"]["driver"] = driver
            malformed.append(report)
        with tempfile.TemporaryDirectory() as directory:
            filename = pathlib.Path(directory) / "rust.sarif"
            for report in malformed:
                with self.subTest(report=report):
                    filename.write_text(json.dumps(report))
                    with self.assertRaises(ValueError):
                        blocking_findings(directory)
            filename.write_text(json.dumps(baseline))
            self.assertEqual(blocking_findings(directory), 0)
            # Invocation records are optional in SARIF, unlike actual results.
            del baseline["runs"][0]["invocations"]
            filename.write_text(json.dumps(baseline))
            self.assertEqual(blocking_findings(directory), 0)
            filename.write_text('{"version":"2.1.0","version":"2.1.0","runs":'
                                + json.dumps(baseline["runs"]) + '}')
            with self.assertRaises(ValueError):
                blocking_findings(directory)

    def test_sast_rejects_failed_or_incomplete_invocations(self):
        invocations = [None, {}, {"executionSuccessful": False}, {"executionSuccessful": 1},
                       {"executionSuccessful": True, "exitCode": 1},
                       {"executionSuccessful": True, "exitSignalName": "SIGTERM"},
                       {"executionSuccessful": True, "exitSignalNumber": False},
                       {"executionSuccessful": True, "toolExecutionNotifications": [{"level": "error"}]},
                       {"executionSuccessful": True, "toolConfigurationNotifications": [{"level": "error"}]}]
        with tempfile.TemporaryDirectory() as directory:
            filename = pathlib.Path(directory) / "rust.sarif"
            for invocation in invocations:
                with self.subTest(invocation=invocation):
                    report = sarif_report()
                    report["runs"][0]["invocations"] = [invocation]
                    filename.write_text(json.dumps(report))
                    with self.assertRaises(ValueError):
                        blocking_findings(directory)

    def test_sast_rejects_invalid_scores_even_without_unsuppressed_results(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = pathlib.Path(directory) / "rust.sarif"
            for score in ["NaN", "Infinity", "-Infinity", "1e309", "invalid", float("nan"),
                          float("inf"), -1, 10.1, True, None, {}, []]:
                for results in [[], [finding("high", suppressions=[{"kind": "external", "status": "accepted"}])]]:
                    with self.subTest(score=score, results=results):
                        report = sarif_report()
                        report["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = score
                        report["runs"][0]["results"] = results
                        filename.write_text(json.dumps(report))
                        with self.assertRaises(ValueError):
                            blocking_findings(directory)

    def test_sast_resolves_rule_indices_and_rejects_ambiguous_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = pathlib.Path(directory) / "rust.sarif"
            report = sarif_report()
            indexed = {"ruleIndex": 0, "message": {"text": "Synthetic test finding"}}
            report["runs"][0]["results"] = [indexed]
            filename.write_text(json.dumps(report))
            self.assertEqual(blocking_findings(directory), 1)
            for result in [finding("missing"), finding("low", ruleIndex=0),
                           finding("high", ruleIndex=-1), finding("high", level="unknown"),
                           finding("high", suppressions={"status": "accepted"})]:
                with self.subTest(result=result):
                    report["runs"][0]["results"] = [result]
                    filename.write_text(json.dumps(report))
                    with self.assertRaises(ValueError):
                        blocking_findings(directory)

    def test_sast_cli_fails_closed_without_emitting_report_content(self):
        with tempfile.TemporaryDirectory() as directory:
            report = sarif_report()
            report["runs"][0]["invocations"][0]["executionSuccessful"] = False
            report["runs"][0]["results"] = [finding("high", message={"text": "PRIVATE_TEST_MARKER"})]
            (pathlib.Path(directory) / "rust.sarif").write_text(json.dumps(report))
            result = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve().parents[1]
                                    / "check_sast.py"), directory], text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("PRIVATE_TEST_MARKER", result.stdout + result.stderr)

    def test_release_source_requires_matching_tag_and_no_dirty_or_untracked_source(self):
        # All commits and tags below exist only in this temporary test repository.
        git_environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        git_environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, git_environment, clear=True):
            root = pathlib.Path(directory)

            def git(*args):
                return subprocess.check_output([
                    "git", "-c", f"core.hooksPath={os.devnull}", "-c", "commit.gpgsign=false",
                    "-c", "tag.gpgsign=false", "-c", "user.name=Atlas Engine Test",
                    "-c", "user.email=test@example.invalid", *args,
                ], cwd=root, text=True, stderr=subprocess.PIPE).strip()

            git("init", "--quiet", "--initial-branch=main")
            with self.assertRaises(ValueError):
                source_revision("v0.1.0", root)
            (root / ".gitignore").write_text("/target/\n/dist/\n*.cdx.json\n")
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
            source = root / "source.rs"
            source.write_text("fn original() {}\n")
            git("add", ".")
            git("commit", "--quiet", "-m", "Synthetic test source")
            with self.assertRaises(ValueError):
                source_revision("v0.1.0", root)
            git("tag", "v0.1.0")
            sha = git("rev-parse", "HEAD")
            with self.assertRaisesRegex(ValueError, "trusted main ancestry"):
                source_revision("v0.1.0", root)
            git("update-ref", "refs/remotes/origin/main", sha)
            self.assertEqual(source_revision("v0.1.0", root), sha)
            with mock.patch("prepare_release.ROOT", root), mock.patch.dict(os.environ, {
                "ATLAS_RELEASE_TAG": "v0.1.0", "ATLAS_RELEASE_TARGET": "aarch64-apple-darwin",
            }), redirect_stdout(io.StringIO()) as output:
                prepare_release(validate_only=True)
                self.assertIn(sha, output.getvalue())
            (root / "target").mkdir()
            (root / "target" / "generated").write_text("ignored build artifact")
            self.assertEqual(source_revision("v0.1.0", root), sha)
            untracked = root / "untracked\nsource.rs"
            untracked.write_text("fn additional() {}\n")
            with self.assertRaises(ValueError):
                source_revision("v0.1.0", root)
            untracked.unlink()
            source.write_text("fn modified() {}\n")
            with self.assertRaises(ValueError):
                source_revision("v0.1.0", root)
            git("add", "source.rs")
            with self.assertRaises(ValueError):
                source_revision("v0.1.0", root)
            git("commit", "--quiet", "-m", "Another synthetic commit")
            with self.assertRaises(ValueError):
                source_revision("v0.1.0", root)  # Existing tag points elsewhere.
            git("tag", "--annotate", "v0.2.0", "-m", "Synthetic annotated tag")
            git("update-ref", "refs/remotes/origin/main", git("rev-parse", "HEAD"))
            self.assertEqual(source_revision("v0.2.0", root), git("rev-parse", "HEAD"))

    def test_release_source_accepts_tag_ancestor_of_local_trusted_main_without_remote(self):
        git_environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        git_environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, git_environment, clear=True):
            root = pathlib.Path(directory)

            def git(*args):
                return subprocess.check_output([
                    "git", "-c", f"core.hooksPath={os.devnull}", "-c", "commit.gpgsign=false",
                    "-c", "tag.gpgsign=false", "-c", "user.name=Atlas Engine Test",
                    "-c", "user.email=test@example.invalid", *args,
                ], cwd=root, text=True, stderr=subprocess.PIPE).strip()

            git("init", "--quiet", "--initial-branch=main")
            (root / "source.rs").write_text("fn release() {}\n")
            git("add", "source.rs")
            git("commit", "--quiet", "-m", "Synthetic release source")
            release_sha = git("rev-parse", "HEAD")
            git("tag", "v0.1.0")
            (root / "source.rs").write_text("fn release() {}\nfn later() {}\n")
            git("commit", "--quiet", "--all", "-m", "Later trusted main source")
            git("update-ref", "refs/remotes/origin/main", git("rev-parse", "HEAD"))
            git("switch", "--quiet", "--detach", release_sha)

            self.assertEqual(git("remote"), "")
            self.assertEqual(source_revision("v0.1.0", root), release_sha)

    def test_release_source_rejects_tag_outside_local_trusted_main_in_both_modes(self):
        git_environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        git_environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, git_environment, clear=True):
            root = pathlib.Path(directory)

            def git(*args):
                return subprocess.check_output([
                    "git", "-c", f"core.hooksPath={os.devnull}", "-c", "commit.gpgsign=false",
                    "-c", "tag.gpgsign=false", "-c", "user.name=Atlas Engine Test",
                    "-c", "user.email=test@example.invalid", *args,
                ], cwd=root, text=True, stderr=subprocess.PIPE).strip()

            git("init", "--quiet", "--initial-branch=main")
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
            (root / "source.rs").write_text("fn base() {}\n")
            git("add", ".")
            git("commit", "--quiet", "-m", "Synthetic base")
            git("switch", "--quiet", "--create", "off-main")
            (root / "source.rs").write_text("fn off_main() {}\n")
            git("commit", "--quiet", "--all", "-m", "Synthetic off-main release")
            off_main_sha = git("rev-parse", "HEAD")
            git("tag", "v0.1.0")
            git("switch", "--quiet", "main")
            (root / "source.rs").write_text("fn trusted_main() {}\n")
            git("commit", "--quiet", "--all", "-m", "Synthetic trusted main")
            git("update-ref", "refs/remotes/origin/main", git("rev-parse", "HEAD"))
            git("switch", "--quiet", "--detach", off_main_sha)

            self.assertEqual(git("remote"), "")
            with mock.patch("prepare_release.ROOT", root), mock.patch.dict(os.environ, {
                "ATLAS_RELEASE_TAG": "v0.1.0", "ATLAS_RELEASE_TARGET": "aarch64-apple-darwin",
            }):
                for validate_only in (True, False):
                    with self.subTest(validate_only=validate_only), self.assertRaisesRegex(
                        ValueError, "trusted main ancestry"
                    ):
                        prepare_release(validate_only=validate_only)


if __name__ == "__main__":
    unittest.main()
