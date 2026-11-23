import ast, sys, yaml, pathlib

GRANT = ("consent", "agree", "accept", "optin", "opt_in")
WITHDRAW = ("withdraw", "revoke", "optout", "opt_out", "unsubscribe", "decline")

def routes(tree):
    """Yield (func_name, path, methods, lineno) for every Flask route."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for d in node.decorator_list:
                if isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "route":
                    path = d.args[0].value if d.args else ""
                    methods = ["GET"]
                    for kw in d.keywords:
                        if kw.arg == "methods":
                            methods = [e.value.upper() for e in kw.value.elts]
                    yield node.name, path, methods, node.lineno

def scan(folder):
    rule = yaml.safe_load(open("rules/DPDP-CONSENT-001.yml"))
    findings = []
    for f in pathlib.Path(folder).rglob("*.py"):
        tree = ast.parse(f.read_text())
        rs = list(routes(tree))
        grants = [r for r in rs if any(k in (r[0] + r[1]).lower() for k in GRANT)
                  and "POST" in r[2] and not any(k in (r[0] + r[1]).lower() for k in WITHDRAW)]
        withdraws = [r for r in rs if any(k in (r[0] + r[1]).lower() for k in WITHDRAW)
                     or ("DELETE" in r[2] and "consent" in r[1].lower())]
        if grants and not withdraws:
            name, path, methods, line = grants[0]
            findings.append((rule, f"{f}:{line}", f"route {methods[0]} {path} grants consent, no withdraw route found"))
    return findings

for rule, where, evidence in scan(sys.argv[1]):
    print(f"[{rule['severity'].upper()}] {rule['id']}  {rule['title']}")
    print(f"  Evidence : {where}  ({evidence})")
    print(f"  Law      : {rule['law']['act']}")
    print(f"             {rule['law']['also']}")
    print(f"  Penalty  : up to {rule['penalty_cap']}")
    print(f"  Why      : {rule['severity_reason']}")
    print(f"  Fix      : {rule['fix']}")
