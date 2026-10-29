#!/usr/bin/env python3
"""ReconScope: low-impact, scope-enforced reconnaissance for authorized testing."""
from __future__ import annotations
import argparse, csv, datetime as dt, fnmatch, hashlib, ipaddress, json, logging, re, shutil, socket, sqlite3, ssl, subprocess, sys, time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]

class Scope:
    def __init__(self, policy: dict):
        self.policy = policy
        def asset(x): return str(x.get("asset", "") if isinstance(x, dict) else x).lower().rstrip(".")
        self.includes = [asset(x) for x in policy.get("in_scope", [])]
        self.excludes = [asset(x) for x in policy.get("out_of_scope", policy.get("exclude", []))]
    def allowed(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        if not host or any(fnmatch.fnmatch(host, x) for x in self.excludes): return False
        return any(fnmatch.fnmatch(host, x) for x in self.includes)
    def reason(self, host: str) -> str:
        return "excluded" if any(fnmatch.fnmatch(host.lower().rstrip("."), x) for x in self.excludes) else ("in-scope" if self.allowed(host) else "not-in-scope")

class ScriptParser(HTMLParser):
    def __init__(self): super().__init__(); self.scripts=[]
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            d = dict(attrs); self.scripts.append(d.get("src")) if d.get("src") else None

def load_policy(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    try: return json.loads(raw)
    except json.JSONDecodeError: pass
    try:
        import yaml
        return yaml.safe_load(raw)
    except ImportError as e:
        raise SystemExit("Policy is not JSON. Install optional YAML support with: pip install -r requirements.txt") from e

def now(): return dt.datetime.now().astimezone().strftime("%Y-%m-%d_%H%M%S")
def program_name(p): return re.sub(r"[^A-Za-z0-9_.-]+", "_", p)[:80] or "program"
def host_name(h): return re.sub(r"[^A-Za-z0-9_.-]+", "_", h.lower())[:253]
def write_json(path, obj): path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
def append_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)

def write_lines(path, values):
    path.write_text("".join(str(x) + "\n" for x in values), encoding="utf-8")

def discovery_commands(root, settings):
    commands={
        "subfinder": ["-silent","-d",root],
        "assetfinder": ["--subs-only",root],
        "sublist3r": ["-d",root,"-n"],
        "chaos": ["-d",root,"-silent"],
        "github-subdomains": ["-d",root,"-raw"],
        "findomain": ["-t",root,"--external-subdomains"],
        "amass": ["enum","-passive","-d",root],
    }
    selected=settings.get("discovery_tools", list(commands))
    if settings.get("disable_amass", False): selected=[x for x in selected if x!="amass"]
    return [(tool, [tool]+commands[tool]) for tool in selected if tool in commands]

def clean_candidates(lines, root):
    result=set()
    for line in lines:
        value=line.strip().lower().rstrip(".").lstrip("*.")
        if value.startswith(("http://","https://")): value=urlparse(value).hostname or ""
        value=value.split()[0] if value else ""
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?",value) and (value==root or value.endswith("."+root)):
            result.add(value)
    return result

def run_discovery(args):
    policy=load_policy(Path(args.policy)); scope=Scope(policy); program=program_name(policy.get("program", "program")); settings=policy.get("settings",{})
    roots=[]
    for item in policy.get("in_scope", []):
        asset=str(item.get("asset",item) if isinstance(item,dict) else item).lower().rstrip(".")
        root=asset[2:] if asset.startswith("*.") else asset
        if root and root not in roots: roots.append(root)
    stamp=now(); base=ROOT/"data"/program; discovered=set(); runs=[]; available=[]
    for tool, _ in discovery_commands("example.invalid", settings):
        if shutil.which(tool): available.append(tool)
    print(f"[1/2] Running sequential passive discovery for {len(roots)} root(s)...")
    if not available: print("  No optional discovery tools found; using exact policy targets only.")
    for root in roots:
        print(f"  discovering: {root}")
        wildcard_root_allowed=any(rule.startswith("*.") and root==rule[2:] for rule in scope.includes)
        if not scope.allowed(root) and not wildcard_root_allowed or any(fnmatch.fnmatch(root,rule) for rule in scope.excludes):
            print(f"  skipped by scope: {root}"); continue
        out_dir=base/host_name(root)/"discovery"/stamp; out_dir.mkdir(parents=True,exist_ok=True); root_found=set(); root_runs=[]
        for tool, template in discovery_commands(root, settings):
            binary=shutil.which(tool)
            if not binary:
                entry={"root":root,"tool":tool,"status":"not installed"}; runs.append(entry); root_runs.append(entry); continue
            try:
                print(f"    {tool}")
                proc=subprocess.run([binary]+template[1:],capture_output=True,text=True,timeout=int(settings.get("discovery_timeout",300)),check=False)
                candidates=clean_candidates(proc.stdout.splitlines(),root); root_found.update(candidates)
                write_lines(out_dir/f"{tool}.txt",sorted(candidates))
                entry={"root":root,"tool":tool,"status":"complete","returncode":proc.returncode,"count":len(candidates),"stderr":proc.stderr[-2000:]}; runs.append(entry); root_runs.append(entry)
            except subprocess.TimeoutExpired:
                write_lines(out_dir/f"{tool}.txt",[]); entry={"root":root,"tool":tool,"status":"timeout"}; runs.append(entry); root_runs.append(entry)
        approved=sorted(x for x in root_found if scope.allowed(x)); discovered.update(root_found)
        write_lines(out_dir/"combined.txt",sorted(root_found)); write_lines(out_dir/"in_scope_targets.txt",approved)
        write_json(out_dir/"metadata.json",{"program":program,"scan":stamp,"root":root,"tools":available,"found":len(root_found),"approved":len(approved),"runs":root_runs})
    approved=sorted(x for x in discovered if scope.allowed(x)); excluded=sorted(x for x in discovered if any(fnmatch.fnmatch(x,rule) for rule in scope.excludes)); unlisted=sorted(set(discovered)-set(approved)-set(excluded))
    print("Discovery complete"); print(f"  Subdomains found: {len(discovered)}"); print(f"  In scope:         {len(approved)}"); print(f"  Out of scope:     {len(excluded)}"); print(f"  Not listed:       {len(unlisted)}"); print("Discovery evidence is stored inside each root target folder.")
    return approved

def run_simple(args):
    if args.edit:
        args.policy = interactive_policy()
    elif not args.policy:
        candidates=sorted((ROOT/"scopes").glob("*/scope.json"))
        candidates += sorted(p for p in (ROOT/"scopes").glob("*.json") if p.name != "example.json")
        if len(candidates)==1 and not args.edit:
            args.policy=str(candidates[0])
            print(f"Using saved policy: {args.policy}")
        else:
            args.policy = interactive_policy()
    if args.discover and not args.dry_run:
        discovered=run_discovery(args)
        args.targets_override=discovered
    return run_scan(args)

def interactive_policy():
    print("ReconScope interactive setup")
    print("Enter only assets you are authorized to test.")
    program=input("Program name: ").strip() or "manual-program"
    def read_block(label):
        print(label)
        print("Paste one hostname per line. Press Enter on an empty line when finished.")
        values=[]
        while True:
            line=input().strip()
            if not line: break
            values.extend(x.strip().lower().rstrip(".") for x in line.split(",") if x.strip())
        return values
    included=read_block("In-scope domains/hostnames:")
    excluded=read_block("Out-of-scope domains/hostnames (optional):")
    if not included: raise SystemExit("At least one in-scope asset is required.")
    policy={"program":program,"in_scope":[{"asset":x,"type":"web"} for x in included],"out_of_scope":[{"asset":x,"reason":"entered during interactive setup"} for x in excluded],"settings":{"request_rate":1,"timeout":5,"max_response_bytes":1048576}}
    path=ROOT/"scopes"/program_name(program)/"scope.json"; path.parent.mkdir(parents=True,exist_ok=True); write_json(path,policy)
    print(f"\nPolicy saved to: {path}")
    return str(path)

def dns(host):
    out=[]
    try:
        for family, _, _, _, addr in socket.getaddrinfo(host, None):
            ip=addr[0]
            if ip not in out: out.append(ip)
    except socket.gaierror as e: return {"host":host,"ips":[],"error":str(e)}
    return {"host":host,"ips":out,"error":""}

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None

def probe(url, timeout, user_agent, max_bytes, extra_headers=None):
    start=time.monotonic(); req=Request(url, headers={"User-Agent":user_agent, "Accept":"text/html,application/xhtml+xml,*/*;q=0.8"})
    if extra_headers: req.headers.update(extra_headers)
    try:
        with build_opener(NoRedirect()).open(req, timeout=timeout) as r:
            body=r.read(max_bytes); headers={k.lower():v for k,v in r.headers.items()}
            return {"url":url,"final_url":r.geturl(),"status":r.status,"headers":headers,"body":body[:max_bytes],"seconds":round(time.monotonic()-start,3),"error":""}
    except HTTPError as e:
        body=e.read(max_bytes) if e.fp else b""; headers={k.lower():v for k,v in e.headers.items()}
        return {"url":url,"final_url":e.geturl(),"status":e.code,"headers":headers,"body":body,"seconds":round(time.monotonic()-start,3),"error":""}
    except Exception as e: return {"url":url,"final_url":"","status":None,"headers":{},"body":b"","seconds":round(time.monotonic()-start,3),"error":str(e)}

def safe_url(scope, url):
    p=urlparse(url); return p.scheme in ("http","https") and scope.allowed(p.hostname or "")

def publicly_routable(host):
    try:
        return all(not (ipaddress.ip_address(x[4][0]).is_private or ipaddress.ip_address(x[4][0]).is_loopback or ipaddress.ip_address(x[4][0]).is_link_local or ipaddress.ip_address(x[4][0]).is_reserved) for x in socket.getaddrinfo(host, None))
    except socket.gaierror: return True
def tls_info(host, timeout):
    try:
        ctx=ssl.create_default_context(); ctx.check_hostname=True
        with socket.create_connection((host,443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                c=s.getpeercert(); return {"host":host,"not_after":c.get("notAfter",""),"subject":str(c.get("subject","")),"error":""}
    except Exception as e: return {"host":host,"not_after":"","subject":"","error":str(e)}

def findings(result, scope, origin):
    h=result["headers"]; out=[]; u=result["final_url"] or result["url"]
    checks=[("missing-csp","Content-Security-Policy"), ("missing-hsts","Strict-Transport-Security"), ("missing-nosniff","X-Content-Type-Options"), ("missing-frame-protection","X-Frame-Options")]
    for key, header in checks:
        if header.lower() not in h: out.append({"id":key,"asset":u,"category":"headers","severity":"low","confidence":"high","evidence":f"Missing {header}","remediation":f"Configure {header} where appropriate."})
    for cookie in h.get("set-cookie", "").split(",") if h.get("set-cookie") else []:
        low=cookie.lower(); missing=[]
        if u.startswith("https://") and "secure" not in low: missing.append("Secure")
        if "httponly" not in low: missing.append("HttpOnly")
        if "samesite" not in low: missing.append("SameSite")
        if missing: out.append({"id":"cookie-attributes","asset":u,"category":"cookies","severity":"low","confidence":"medium","evidence":"Missing: "+", ".join(missing),"remediation":"Review cookie security attributes."})
    if "access-control-allow-origin" in h and origin in h["access-control-allow-origin"]:
        out.append({"id":"cors-reflection","asset":u,"category":"cors","severity":"medium","confidence":"medium","evidence":f"Test Origin {origin!r} was reflected","remediation":"Allow only required trusted origins; assess credentialed impact manually."})
    return out

def run_scan(args):
    policy=load_policy(Path(args.policy)); scope=Scope(policy); program=program_name(policy.get("program", "program")); settings=policy.get("settings", {})
    rate=float(args.rate or settings.get("request_rate", 1)); timeout=float(settings.get("timeout",5)); max_bytes=int(settings.get("max_response_bytes",1048576)); ua=settings.get("user_agent","ReconScope/1.0 (authorized security testing)")
    targets=[]
    # Concrete targets may be supplied directly in the policy. Every one is
    # still checked against in_scope and out_of_scope before any request.
    for item in policy.get("targets", []):
        h=str(item.get("asset", item) if isinstance(item, dict) else item).lower().rstrip(".")
        if h and scope.allowed(h): targets.append(h)
    for item in policy.get("in_scope", []):
        asset=str(item.get("asset",item)).lower().rstrip(".") if isinstance(item,dict) else str(item).lower().rstrip(".")
        if "*" not in asset and scope.allowed(asset): targets.append(asset)
    for f in policy.get("local_targets", []):
        for line in Path(f).read_text().splitlines():
            h=line.strip().lower().rstrip(".")
            if h and not h.startswith("#") and scope.allowed(h): targets.append(h)
    if args.targets_file:
        for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines():
            h=line.strip().lower().rstrip(".")
            if h and not h.startswith("#") and scope.allowed(h): targets.append(h)
    for h in getattr(args, "targets_override", []):
        if scope.allowed(h): targets.append(h)
    targets=sorted(set(targets)); stamp=now(); base=ROOT/"data"/program
    if args.target: targets=[x for x in targets if x==args.target.lower().rstrip(".")]
    if args.dry_run:
        print(json.dumps({"program":program,"targets":targets,"excluded":policy.get("out_of_scope",policy.get("exclude",[])),"rate":rate},indent=2)); return
    if not targets: raise SystemExit("No concrete in-scope targets. Add exact assets or local_targets; wildcards need discovered names.")
    print(f"[2/2] Scanning {len(targets)} authorized target(s) at approximately {rate:g} request/s per request...")
    scan_dirs=[]; all_findings=[]; http_rows=[]; dns_rows=[]; js_rows=[]; decisions=[]
    for host in targets:
        print(f"  scanning: {host}")
        d=base/host_name(host)/"scans"/stamp; d.mkdir(parents=True,exist_ok=True); scan_dirs.append(d)
        decisions.append({"host":host,"allowed":scope.allowed(host),"reason":scope.reason(host)})
        dr=dns(host); dns_rows.append(dr); write_json(d/"dns.json",dr)
        if settings.get("block_private_addresses", True) and dr["ips"] and not publicly_routable(host):
            decisions[-1]["allowed"] = False; decisions[-1]["reason"] = "resolved to private, loopback, link-local, or reserved address"; continue
        for scheme in ("https","http"):
            url=f"{scheme}://{host}/"
            if not safe_url(scope,url): continue
            if rate>0: time.sleep(1/rate)
            r=probe(url,timeout,ua,max_bytes); final=r["final_url"]
            if final and not safe_url(scope,final): r["error"]="redirect escaped scope"; r["final_url"]=""
            row={k:r[k] for k in ("url","final_url","status","seconds","error")}; row["title"]=""; row["content_type"]=r["headers"].get("content-type",""); row["server"]=r["headers"].get("server",""); http_rows.append(row)
            if r["status"] is not None:
                marker="SUSPICIOUS" if r["status"] in (401,403,429) or 500<=r["status"]<600 else "LIVE"
                print(f"    [{marker}] {r['status']} {url}")
            elif r["error"]:
                print(f"    [ERROR] {url} - {r['error']}")
            if r["status"] is not None:
                origin=f"https://reconscope.invalid"
                all_findings.extend(findings(r,scope,origin))
                if settings.get("cors_checks", True):
                    if rate>0: time.sleep(1/rate)
                    cors=probe(url,timeout,ua,max_bytes,{"Origin":origin})
                    all_findings.extend(findings(cors,scope,origin))
                if r["body"] and "text/html" in row["content_type"].lower():
                    text=r["body"].decode("utf-8","replace"); m=re.search(r"<title[^>]*>(.*?)</title>",text,re.I|re.S); row["title"]=re.sub(r"\s+"," ",m.group(1)).strip() if m else ""
                    sp=ScriptParser(); sp.feed(text)
                    for src in sp.scripts:
                        u=urljoin(final or url,src)
                        if safe_url(scope,u): js_rows.append({"host":host,"url":u,"sha256":"","indicators":""})
            if scheme=="https": write_json(d/"tls.json",tls_info(host,timeout))
        append_csv(d/"http.csv",[x for x in http_rows if x["url"].endswith(host+"/")], ["url","final_url","status","seconds","error","title","content_type","server"])
    summary={"program":program,"scan":stamp,"targets":targets,"dns":dns_rows,"http":http_rows,"javascript":js_rows,"findings":all_findings,"scope_decisions":decisions}
    for d in scan_dirs:
        target=d.parents[1].name
        target_http=[x for x in http_rows if (urlparse(x["url"]).hostname or "").lower()==target]
        target_summary={**summary,"targets":[target],"dns":[x for x in dns_rows if x["host"]==target],"http":target_http,"javascript":[x for x in js_rows if x["host"]==target],"findings":[x for x in all_findings if (urlparse(x.get("asset","")).hostname or "").lower()==target]}
        write_json(d/"scope_policy.json",policy); write_json(d/"scope_decision.json",next(x for x in decisions if x["host"]==target))
        write_lines(d/"targets.txt",[target]); append_csv(d/"http_results.csv",target_http,["url","final_url","status","seconds","error","title","content_type","server"])
        write_lines(d/"live_hosts.txt",[x["url"] for x in target_summary["http"] if x.get("status") is not None])
        suspicious=[x for x in target_http if x.get("error") or x.get("status") in (401,403,429) or (isinstance(x.get("status"),int) and 500<=x["status"]<600)]
        write_lines(d/"suspicious_hosts.txt",[f"{x['status'] or 'ERROR'}\t{x['url']}\t{x.get('error','')}" for x in suspicious])
        write_json(d/"findings.json",target_summary["findings"])
        write_json(d/"summary.json",target_summary)
        write_json(d/"latest_report.json",target_summary); write_json(d.parent.parent/"latest_report.json",target_summary)
    print(f"Scan complete: {program} ({stamp})\nTargets: {len(targets)} | HTTP results: {len(http_rows)} | Findings: {len(all_findings)}\nTarget evidence: {base}/<target>/scans/{stamp}/")

def main():
    ap=argparse.ArgumentParser(prog="reconscope",description="Low-impact, scope-enforced reconnaissance for authorized testing."); sub=ap.add_subparsers(dest="cmd",required=True)
    doc=sub.add_parser("doctor"); doc.add_argument("--tools",action="store_true",help="show optional external tool availability")
    sc=sub.add_parser("scope",help="inspect policy scope"); sc.add_argument("action",choices=["check"]); sc.add_argument("--policy",required=True)
    d=sub.add_parser("discover",help="optional passive Subfinder discovery; does not probe hosts"); d.add_argument("--policy",required=True)
    r=sub.add_parser("run",help="automatic serial workflow; omit policy to reuse one saved policy or be prompted"); r.add_argument("policy",nargs="?"); r.add_argument("--new","--edit",dest="edit",action="store_true",help="create or rewrite a policy interactively"); r.add_argument("--no-discover",dest="discover",action="store_false",help="skip passive Subfinder discovery"); r.add_argument("--dry-run",action="store_true"); r.add_argument("--rate",type=float); r.set_defaults(target=None,targets_file=None,discover=True,edit=False)
    s=sub.add_parser("scan"); s.add_argument("--policy",required=True); s.add_argument("--target"); s.add_argument("--targets-file",help="additional concrete targets, such as discovery/in_scope_targets.txt"); s.add_argument("--rate",type=float); s.add_argument("--dry-run",action="store_true")
    for name in ("report","diff"):
        p=sub.add_parser(name); p.add_argument("--program",required=True); p.add_argument("--target",required=True)
    a=ap.parse_args()
    if a.cmd=="doctor":
        print(f"Python: {sys.version.split()[0]}\nRoot: {ROOT}\nStatus: ready (standard library mode)")
        if a.tools:
            print("\nOptional tools:")
            for name in ("subfinder","assetfinder","sublist3r","chaos","github-subdomains","findomain","amass","httpx","dnsx","katana","gau","waybackurls","ffuf","nuclei"):
                state=shutil.which(name) or "not installed"
                note=" [intentionally disabled]" if name in ("ffuf","nuclei") else ""
                print(f"- {name}: {state}{note}")
        return
    if a.cmd=="scope":
        p=load_policy(Path(a.policy)); s=Scope(p); print(json.dumps({"program":p.get("program","program"),"in_scope":s.includes,"out_of_scope":s.excludes,"precedence":"exclusions override inclusions"},indent=2)); return
    if a.cmd=="discover": return run_discovery(a)
    if a.cmd=="run":
        a.policy=a.policy
        return run_simple(a)
    if a.cmd=="scan": return run_scan(a)
    base=ROOT/"data"/program_name(a.program)/host_name(a.target)
    if a.cmd=="report": print((base/"latest_report.json").read_text() if (base/"latest_report.json").exists() else "No report found."); return
    reports=sorted((ROOT/"data"/program_name(a.program)/host_name(a.target)/"scans").glob("*/latest_report.json"))
    if len(reports)<2: print("At least two scans are required for a diff."); return
    old,new=json.loads(reports[-2].read_text()),json.loads(reports[-1].read_text()); oldh={x["url"]:x for x in old.get("http",[])}; newh={x["url"]:x for x in new.get("http",[])}
    print(json.dumps({"new_urls":sorted(set(newh)-set(oldh)),"removed_urls":sorted(set(oldh)-set(newh)),"status_changes":{u:[oldh[u].get("status"),newh[u].get("status")] for u in set(oldh)&set(newh) if oldh[u].get("status")!=newh[u].get("status")}},indent=2))
if __name__=="__main__": main()
