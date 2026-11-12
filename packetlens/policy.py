"""Policy loading and validation for PacketLens detection rules."""
import ipaddress
import json
import math
from pathlib import Path


PARAM_TYPES = {
    "port_scan": {
        "windows": "windows", "cooldown": "positive",
    },
    "syn_flood": {
        "threshold": "positive_int", "cooldown": "positive",
    },
    "dns_tunnel": {
        "span": "positive", "min_unique": "positive_int", "min_avg_len": "positive",
        "min_avg_entropy": "positive", "cooldown": "positive",
    },
    "arp_spoof": {"cooldown": "positive"},
    "horizontal_scan": {
        "window_s": "positive", "min_hosts": "positive_int", "ignore_ports": "ports",
        "cooldown": "positive",
    },
    "volumetric": {
        "metrics": "metrics", "alpha": "alpha", "z": "positive",
        "warmup": "positive_int", "rearm": "positive_int",
    },
}
DETECTORS = set(PARAM_TYPES)
SEVERITIES = {"low", "medium", "high", "critical"}
METRICS = {"packets", "bytes", "syn", "dns", "sources"}


class Policy:
    """Validated policy data; detector and allowlist entries remain JSON-compatible."""

    def __init__(self, value):
        errors = validate_policy(value)
        if errors:
            raise ValueError("Invalid policy:\n" + "\n".join(f"- {error}" for error in errors))
        self.value = json.loads(json.dumps(value))
        self.name = self.value["name"]
        self.incident_gap_s = self.value["incident_gap_s"]
        self.policies = self.value["policies"]

    def to_dict(self):
        return json.loads(json.dumps(self.value))


def validate_policy(value):
    """Return every policy validation error, each prefixed by its JSON path."""
    errors = []

    def error(path, message):
        errors.append(f"{path}: {message}")

    if not isinstance(value, dict):
        return ["$: expected an object"]
    allowed_root = {"version", "name", "incident_gap_s", "policies"}
    for key in value.keys() - allowed_root:
        error(f"$.{key}", "unknown property")
    for key in ("version", "name", "incident_gap_s", "policies"):
        if key not in value:
            error(f"$.{key}", "required property is missing")
    if "version" in value and (type(value["version"]) is not int or value["version"] != 1):
        error("$.version", "must be the integer 1")
    if "name" in value and (not isinstance(value["name"], str) or not value["name"]):
        error("$.name", "must be a non-empty string")
    if "incident_gap_s" in value:
        gap = value["incident_gap_s"]
        if isinstance(gap, bool) or not isinstance(gap, (int, float)):
            error("$.incident_gap_s", "must be a number")
        elif not math.isfinite(gap) or gap <= 0:
            error("$.incident_gap_s", "must be positive")
    rules = value.get("policies")
    if not isinstance(rules, list):
        if "policies" in value:
            error("$.policies", "must be an array")
        return errors

    seen_ids = set()
    for index, rule in enumerate(rules):
        path = f"$.policies[{index}]"
        if not isinstance(rule, dict):
            error(path, "must be an object")
            continue
        allowed = {"id", "detector", "enabled", "experimental", "severity", "action",
                   "incident_gap_s", "params", "allowlist", "description"}
        for key in rule.keys() - allowed:
            error(f"{path}.{key}", "unknown property")
        for key in ("id", "detector", "enabled", "action"):
            if key not in rule:
                error(f"{path}.{key}", "required property is missing")
        rule_id = rule.get("id")
        if "id" in rule:
            if not isinstance(rule_id, str) or not rule_id:
                error(f"{path}.id", "must be a non-empty string")
            elif rule_id in seen_ids:
                error(f"{path}.id", f"duplicate id {rule_id!r}")
            else:
                seen_ids.add(rule_id)
        detector = rule.get("detector")
        valid_detector = isinstance(detector, str) and detector in DETECTORS
        if "detector" in rule and not valid_detector:
            error(f"{path}.detector", f"unknown detector {detector!r}")
        if "enabled" in rule and type(rule["enabled"]) is not bool:
            error(f"{path}.enabled", "must be a boolean")
        if "experimental" in rule and type(rule["experimental"]) is not bool:
            error(f"{path}.experimental", "must be a boolean")
        if ("severity" in rule and
                (not isinstance(rule["severity"], str) or rule["severity"] not in SEVERITIES)):
            error(f"{path}.severity", f"must be one of {', '.join(sorted(SEVERITIES))}")
        if ("action" in rule and
                (not isinstance(rule["action"], str) or rule["action"] not in {"alert", "log"})):
            error(f"{path}.action", 'must be "alert" or "log"')
        if "incident_gap_s" in rule:
            gap = rule["incident_gap_s"]
            if isinstance(gap, bool) or not isinstance(gap, (int, float)):
                error(f"{path}.incident_gap_s", "must be a number")
            elif not math.isfinite(gap) or gap <= 0:
                error(f"{path}.incident_gap_s", "must be positive")
        if "description" in rule and not isinstance(rule["description"], str):
            error(f"{path}.description", "must be a string")

        params = rule.get("params", {})
        if not isinstance(params, dict):
            error(f"{path}.params", "must be an object")
            params = {}
        if valid_detector:
            expected = PARAM_TYPES[detector]
            for key in params.keys() - expected.keys():
                error(f"{path}.params.{key}", "unknown parameter")
            for key, value_for_param in params.items():
                if key not in expected:
                    continue
                ppath = f"{path}.params.{key}"
                kind = expected[key]
                if kind == "windows":
                    if not isinstance(value_for_param, list) or not value_for_param:
                        error(ppath, "must be a non-empty array of [window_seconds, threshold] pairs")
                    else:
                        for wi, pair in enumerate(value_for_param):
                            if (not isinstance(pair, list) or len(pair) != 2 or
                                    any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in pair)):
                                error(f"{ppath}[{wi}]", "must be a [number, number] pair")
                            elif (not math.isfinite(pair[0]) or not math.isfinite(pair[1]) or
                                  pair[0] <= 0 or pair[1] <= 0):
                                error(f"{ppath}[{wi}]", "window and threshold must be positive")
                elif kind == "positive":
                    if isinstance(value_for_param, bool) or not isinstance(value_for_param, (int, float)):
                        error(ppath, "must be a number")
                    elif not math.isfinite(value_for_param) or value_for_param <= 0:
                        error(ppath, "must be positive")
                elif kind == "positive_int":
                    if type(value_for_param) is not int:
                        error(ppath, "must be an integer")
                    elif value_for_param <= 0:
                        error(ppath, "must be positive")
                elif kind == "ports":
                    if not isinstance(value_for_param, list):
                        error(ppath, "must be an array of integer ports")
                    else:
                        for pi, port in enumerate(value_for_param):
                            if type(port) is not int or not 0 <= port <= 65535:
                                error(f"{ppath}[{pi}]", "must be an integer from 0 to 65535")
                elif kind == "metrics":
                    if (not isinstance(value_for_param, list) or
                            any(not isinstance(metric, str) or metric not in METRICS
                                for metric in value_for_param)):
                        error(ppath, f"must be an array containing only {', '.join(sorted(METRICS))}")
                elif kind == "alpha":
                    if (isinstance(value_for_param, bool) or
                            not isinstance(value_for_param, (int, float))):
                        error(ppath, "must be a number")
                    elif not math.isfinite(value_for_param) or not 0 < value_for_param <= 1:
                        error(ppath, "must be greater than 0 and at most 1")

        allowlist = rule.get("allowlist", {})
        if not isinstance(allowlist, dict):
            error(f"{path}.allowlist", "must be an object")
            allowlist = {}
        for key in allowlist.keys() - {"src", "dst"}:
            error(f"{path}.allowlist.{key}", "unknown property")
        for key in ("src", "dst"):
            entries = allowlist.get(key, [])
            if not isinstance(entries, list):
                error(f"{path}.allowlist.{key}", "must be an array")
                continue
            for ai, entry in enumerate(entries):
                apath = f"{path}.allowlist.{key}[{ai}]"
                if not isinstance(entry, str):
                    error(apath, "must be an IP address, CIDR, or placeholder")
                    continue
                if entry in {"many", "-"}:
                    continue
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    error(apath, f"invalid IP address or CIDR {entry!r}")
    return errors


def load_policy(path):
    """Read and validate a JSON policy, raising one error with all schema problems."""
    try:
        with open(path, encoding="utf-8") as stream:
            value = json.load(stream)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    except OSError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    return Policy(value)


def default_policy_path():
    return Path(__file__).with_name("policies") / "default.json"


def effective_policy(path=None):
    """Load an explicit policy, or the packaged baseline used by `policy show`."""
    return load_policy(path or default_policy_path())


def rule_matches(rule, src, dst):
    """Match allowlist addresses without treating aggregate source labels as IPs."""
    for field, address in (("src", src), ("dst", dst)):
        if address in {"many", "-", ""}:
            continue
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        for item in rule.get("allowlist", {}).get(field, []):
            if item in {"many", "-"}:
                continue
            try:
                if ip in ipaddress.ip_network(item, strict=False):
                    return True
            except ValueError:
                continue
    return False
