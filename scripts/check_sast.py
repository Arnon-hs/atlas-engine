#!/usr/bin/env python3
"""Fail CodeQL CI on incomplete reports or unsuppressed findings scored >= 7.0."""

import json
import math
import pathlib
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate SARIF object key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("non-standard JSON numeric constant")


def security_score(rule):
    properties = rule.get("properties", {})
    require(isinstance(properties, dict), "invalid rule properties")
    if "security-severity" not in properties:
        return 0.0
    raw = properties["security-severity"]
    require(type(raw) in (str, int, float), "invalid security severity type")
    try:
        score = float(raw)
    except (ValueError, OverflowError):
        raise ValueError("invalid security severity") from None
    require(math.isfinite(score) and 0 <= score <= 10, "invalid security severity range")
    return score


def validate_invocations(run):
    invocations = run.get("invocations", [])
    require(isinstance(invocations, list), "invalid invocation list")
    for invocation in invocations:
        require(isinstance(invocation, dict), "invalid invocation")
        require(invocation.get("executionSuccessful") is True, "incomplete SAST invocation")
        if "exitCode" in invocation:
            require(type(invocation["exitCode"]) is int and invocation["exitCode"] == 0,
                    "unsuccessful SAST exit code")
        if "exitSignalName" in invocation:
            require(isinstance(invocation["exitSignalName"], str) and not invocation["exitSignalName"],
                    "SAST invocation terminated by signal or has an invalid signal name")
        if "exitSignalNumber" in invocation:
            require(type(invocation["exitSignalNumber"]) is int and invocation["exitSignalNumber"] == 0,
                    "SAST invocation terminated by signal or has an invalid signal number")
        for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            notifications = invocation.get(key, [])
            require(isinstance(notifications, list), "invalid invocation notifications")
            for notification in notifications:
                require(isinstance(notification, dict), "invalid invocation notification")
                level = notification.get("level", "warning")
                require(level in ("none", "note", "warning", "error"), "invalid notification level")
                require(level != "error", "SAST invocation reported an error")


def blocking_findings(directory):
    files = sorted(pathlib.Path(directory).glob("*.sarif"))
    if not files:
        raise ValueError("no SARIF results found")
    blocking = 0
    for filename in files:
        report = json.loads(filename.read_text(), parse_constant=reject_constant,
                            object_pairs_hook=unique_object)
        require(isinstance(report, dict) and report.get("version") == "2.1.0",
                "unexpected SARIF document/version")
        require(isinstance(report.get("runs"), list) and bool(report["runs"]),
                "SARIF must contain an analysis run")
        for run in report["runs"]:
            require(isinstance(run, dict), "invalid SARIF run")
            # Omitted results are a rules-metadata export, not an actual scan.
            require(isinstance(run.get("results"), list), "SARIF scan results are missing")
            validate_invocations(run)
            tool = run.get("tool")
            require(isinstance(tool, dict) and isinstance(tool.get("driver"), dict),
                    "invalid SARIF tool")
            extensions = tool.get("extensions", [])
            require(isinstance(extensions, list), "invalid SARIF tool extensions")
            components = [tool["driver"], *extensions]
            rules = {}
            for component in components:
                require(isinstance(component, dict) and isinstance(component.get("name"), str)
                        and bool(component["name"]), "invalid SARIF tool component")
                component_rules = component.get("rules", [])
                require(isinstance(component_rules, list), "invalid SARIF rules")
                for rule in component_rules:
                    require(isinstance(rule, dict) and isinstance(rule.get("id"), str)
                            and bool(rule["id"]) and rule["id"] not in rules, "invalid/ambiguous SARIF rule")
                    configuration = rule.get("defaultConfiguration", {})
                    require(isinstance(configuration, dict), "invalid rule configuration")
                    level = configuration.get("level", "warning")
                    require(level in ("none", "note", "warning", "error"), "invalid rule level")
                    # Validate even unused/suppressed rule scores before filtering.
                    rules[rule["id"]] = (security_score(rule), level)
            for result in run["results"]:
                require(isinstance(result, dict), "invalid SARIF result")
                message = result.get("message")
                require(isinstance(message, dict) and any(isinstance(message.get(key), str)
                        and bool(message[key]) for key in ("text", "markdown", "id")),
                        "missing SARIF result message")
                rule_id = result.get("ruleId")
                if "ruleIndex" in result:
                    index = result["ruleIndex"]
                    driver_rules = tool["driver"].get("rules", [])
                    require(type(index) is int and 0 <= index < len(driver_rules), "invalid rule index")
                    indexed_id = driver_rules[index]["id"]
                    require(rule_id is None or rule_id == indexed_id, "inconsistent rule reference")
                    rule_id = indexed_id
                require(isinstance(rule_id, str) and rule_id in rules, "unresolved SARIF result rule")
                score, default_level = rules[rule_id]
                level = result.get("level", default_level)
                require(level in ("none", "note", "warning", "error"), "invalid result level")
                suppressions = result.get("suppressions", [])
                require(isinstance(suppressions, list), "invalid SARIF suppressions")
                for item in suppressions:
                    require(isinstance(item, dict) and item.get("kind") in ("inSource", "external")
                            and item.get("status") in (None, "accepted", "underReview", "rejected"),
                            "invalid SARIF suppression")
                if any(item.get("status") == "accepted" for item in suppressions):
                    continue  # Suppressions require the review recorded in policy.
                if score >= 7.0 or (not score and level == "error"):
                    blocking += 1
    return blocking


if __name__ == "__main__":
    try:
        count = blocking_findings(sys.argv[1])
    except (OSError, ValueError):
        print("SAST policy: invalid or incomplete SARIF report (no source excerpts emitted).", file=sys.stderr)
        raise SystemExit(2) from None
    print(f"SAST policy: {count} blocking findings (no source excerpts emitted).")
    raise SystemExit(1 if count else 0)
