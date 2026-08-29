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
from prepare_release import (main as prepare_release, release_identity, source_revision,
                             validate_prepared_assets)


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


RELEASE_NAME = "atlas-engine-v0.4.0-aarch64-apple-darwin"
LICENSE_PATH = "synthetic-1.0.0/LICENSE"
LICENSE_TEXT = b"Synthetic MIT license text.\n"


def add_regular_member(package, name, contents=b"adversarial member\n"):
    member = tarfile.TarInfo(name)
    member.mode = 0o644
    member.size = len(contents)
    package.addfile(member, io.BytesIO(contents))


def prepared_assets(output, *, extra_member=None, include_license=True,
                    actual_license=LICENSE_TEXT, declared_license=LICENSE_TEXT,
                    required_directory=None):
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
        "target": "aarch64-apple-darwin",
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
    sbom.write_text('{"bomFormat":"CycloneDX"}\n')
    release.write_text('{"engine_version":"0.4.0"}\n')
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
