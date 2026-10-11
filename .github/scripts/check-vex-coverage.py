#!/usr/bin/env python3
# usage: check-vex-coverage.py SCAN.json SBOM.json VEX.json OUT.json
import hashlib, json, sys, datetime as dt

MAX_DB_AGE_DAYS, MIN_COMPONENTS = 3, 100

def find_key(o, key):
    if isinstance(o, dict):
        if key in o: return o[key]
        o = list(o.values())
    if isinstance(o, list):
        for v in o:
            r = find_key(v, key)
            if r is not None: return r

def lists_pkg(stmt, name):
    subs = [c.get("@id", "") for p in stmt.get("products", []) for c in p.get("subcomponents", [])]
    return not subs or any(f"/{name}@" in s for s in subs)

def ok_status(s, severity):
    st = s.get("status")
    if st == "fixed": return True
    if st == "not_affected": return bool(s.get("justification") or s.get("impact_statement"))
    # accepted risk: only below the HIGH gate, and only with a written action statement
    if st == "affected": return severity in ("Medium", "Low", "Negligible") and bool(s.get("action_statement"))
    return False

def main(scan_p, sbom_p, vex_p, out_p):
    scan, sbom, vex = (json.load(open(p)) for p in (scan_p, sbom_p, vex_p))
    sha = {k: hashlib.sha256(open(q, 'rb').read()).hexdigest() for k, q in (('scan', scan_p), ('sbom', sbom_p), ('vex', vex_p))}
    problems, covered, uncovered, seen = [], [], [], set()
    n = len(sbom.get("components", []))
    if n < MIN_COMPONENTS:
        problems.append(f"control: SBOM has only {n} components")
    desc = scan.get("descriptor", {})
    built = find_key(desc.get("db", {}), "built")
    try:
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(str(built).replace("Z", "+00:00"))).days
        if age > MAX_DB_AGE_DAYS: problems.append(f"vulnerability DB is {age} days old")
    except Exception:
        problems.append("cannot read the vulnerability DB build date from the scan")
    by_id = {}
    for s in vex.get("statements", []):
        v = s.get("vulnerability", {})
        for i in {v.get("name"), *v.get("aliases", [])} - {None}:
            by_id.setdefault(i, []).append(s)
    for m in scan.get("matches", []):
        ids = {m["vulnerability"]["id"], *(r["id"] for r in m.get("relatedVulnerabilities", []))}
        seen |= ids
        pkg = m["artifact"]
        hit = [s for i in ids for s in by_id.get(i, []) if ok_status(s, m["vulnerability"].get("severity")) and lists_pkg(s, pkg["name"])]
        row = {"ids": sorted(ids), "package": pkg["name"], "version": pkg.get("version")}
        (covered if hit else uncovered).append({**row, "status": hit[0]["status"]} if hit else row)
    unused = sorted(i for i in by_id if i not in seen)
    verdict = "pass" if not problems and not uncovered else "fail"
    json.dump({"verdict": verdict, "scanner": desc.get("name"), "scanner_version": desc.get("version"),
               "db_built": built, "sbom_components": n, "findings": len(covered) + len(uncovered),
               "covered": covered, "uncovered": uncovered, "problems": problems,
               "vex_statements_without_finding": unused, "input_sha256": sha}, open(out_p, "w"), indent=2, sort_keys=True)
    print(f"{verdict}: {len(covered)} covered, {len(uncovered)} uncovered, problems={problems}")
    return 0 if verdict == "pass" else 1

sys.exit(main(*sys.argv[1:5]))
