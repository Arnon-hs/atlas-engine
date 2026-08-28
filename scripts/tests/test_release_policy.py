import copy
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from check_sast import blocking_findings
from prepare_release import main as prepare_release, release_identity, source_revision


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


class ReleasePolicyTests(unittest.TestCase):
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
            self.assertEqual(source_revision("v0.2.0", root), git("rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
