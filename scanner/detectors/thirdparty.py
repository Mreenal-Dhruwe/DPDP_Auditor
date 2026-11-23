"""Third-party and transfer detectors: DPDP-TP-001 (personal data sent to SDKs) and
DPDP-TP-002 (data stored or sent outside India - reported as info).

Implemented: DPDP-TP-001, for Python. Only SDKs that are actually imported in the file
count (so a home-made `Analytics` class is ignored):
- module calls:   sentry_sdk.set_user({...}), analytics.identify(...), posthog.capture(...)
- client objects: mp = Mixpanel(token); mp.track(...), mp.people_set(...)
The arguments of the sending call are searched for personal data with PiiRefs. A
pseudonymous id (user_id) is fine; that is exactly what the fix recommends.
"""

import ast

from scanner.detectors.pii_refs import PiiRefs, best_confidence
from scanner.detectors.source import dotted_name, is_test_file, python_trees
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher

TP_001 = "DPDP-TP-001"
# top-level package -> vendor name shown in the evidence
SDK_PACKAGES = {
    "mixpanel": "Mixpanel", "analytics": "Segment", "segment": "Segment", "sentry_sdk": "Sentry",
    "posthog": "PostHog", "amplitude": "Amplitude", "clevertap": "CleverTap", "firebase_admin": "Firebase",
    "moengage": "MoEngage", "intercom": "Intercom", "braze": "Braze", "rudderstack": "RudderStack",
    "newrelic": "New Relic", "datadog": "Datadog", "hubspot": "HubSpot", "customerio": "Customer.io",
}
# SDKs that track behaviour or market to people (error monitoring such as Sentry is neither).
TRACKING_VENDORS = {"Mixpanel", "Segment", "PostHog", "Amplitude", "CleverTap", "MoEngage", "Intercom", "Braze",
                    "RudderStack", "HubSpot", "Customer.io"}
SEND_METHODS = {
    "track", "identify", "alias", "group", "page", "screen", "people_set", "people_set_once",
    "people_append", "set_user", "set_context", "set_tag", "set_extra", "capture", "capture_message",
    "capture_event", "log_event", "send", "push", "profile", "event", "upload", "set", "update",
}


def _sdk_names(tree: ast.Module) -> dict[str, str]:
    """Names in this file that refer to an imported SDK module or class -> vendor."""
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in SDK_PACKAGES:
                    names[(alias.asname or alias.name).split(".")[0]] = SDK_PACKAGES[root]
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in SDK_PACKAGES:
            for alias in node.names:
                names[alias.asname or alias.name] = SDK_PACKAGES[node.module.split(".")[0]]
    return names


def _clients(tree: ast.Module, sdk: dict[str, str]) -> dict[str, str]:
    """Variables holding an SDK client: mp = Mixpanel(token) -> {"mp": "Mixpanel"}."""
    clients = dict(sdk)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            root = dotted_name(node.value.func).split(".")[0]
            if root in sdk:
                for target in node.targets:
                    name = dotted_name(target)
                    if name:
                        clients[name] = sdk[root]
    return clients


def pii_to_third_parties(project: Project) -> list[Hit]:
    matcher = default_matcher()
    hits = []
    for rel, tree in python_trees(project):
        sdk = _sdk_names(tree)
        if not sdk:
            continue
        clients = _clients(tree, sdk)
        lines = project.read_text(rel).splitlines()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            receiver = dotted_name(node.func.value)
            vendor = clients.get(receiver) or clients.get(receiver.split(".")[0])
            if vendor is None or node.func.attr not in SEND_METHODS:
                continue
            refs = PiiRefs(matcher)
            for arg in node.args + [kw.value for kw in node.keywords]:
                refs.visit(arg)
            if not refs.found:
                continue
            hits.append(Hit(
                rule_id=TP_001, file=rel, line=node.lineno, pii=sorted(refs.found),
                evidence=f"{lines[node.lineno - 1].strip()}  [{', '.join(sorted(refs.found))} sent to {vendor}]",
                confidence="low" if is_test_file(rel) else best_confidence(refs.found),
            ))
    return sorted(hits, key=lambda h: (h.file, h.line))
