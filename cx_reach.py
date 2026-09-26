#!/usr/bin/env python3
"""
cx_reach.py - triage Checkmarx SCA findings for a Maven / Spring Boot project.

For every vulnerable library in a Checkmarx export it answers:
  * Is the library actually in the resolved dependency tree, and in which scope?
  * Which of your direct dependencies drags it in?
  * Does your code (directly, or through other libraries) reference its classes?
    (class-level reachability computed from bytecode with the JDK's `jdeps`)
  * If you supply hints for a CVE: are the *vulnerable* classes reachable?
  * Could Spring Boot load it without any static reference (auto-configuration,
    ServiceLoader/SPI registrations)?  Is it mentioned in your application config?
  * Optionally (--osv): is the resolved version really affected, and what's the fix version?

Verdicts, from most to least urgent:
  REACHABLE     vulnerable classes (from --hints) are reachable from your code
  USED          your code reaches classes of the library (no hints to narrow it down)
  USED-SAFE?    library is used, but none of the hinted vulnerable classes are reached
  AUTOCONFIG    no path from your code, but a Spring Boot auto-configuration uses it
  FRAMEWORK     no path from your code, but code loaded by name (spring.factories,
                ServiceLoader) reaches it - e.g. Spring Boot parsing application.yml
  UNUSED        on the runtime classpath but nothing references it -> exclusion candidate
  NOT-SHIPPED   only in test/provided/system scope
  NOT-AFFECTED  (--osv) the resolved version is not affected by this CVE
  NOT-FOUND     not in the dependency tree (already removed/upgraded, or name mismatch)

This is triage, not proof: class-level reachability over-approximates (a referenced
class isn't necessarily a called method) and cannot see arbitrary reflection. Use it to
decide what to exclude, what to upgrade first and what to look at by hand.

Requirements: Python 3.8+, a JDK 11+ (for jdeps), Maven (or the project's ./mvnw).
No third-party Python packages.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

DEP_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1"
RUNTIME_SCOPES = {"compile", "runtime"}
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.I)
GENERIC_TOKENS = {"commons", "spring", "org", "java", "javax", "jakarta", "core", "api",
                  "lib", "common", "client", "server", "boot", "starter", "embed", "impl"}
APP = "<your code>"


# --------------------------------------------------------------------------- findings
@dataclass
class Finding:
    cve: str
    package: str                 # as written in the report
    group: Optional[str]
    artifact: str
    version: Optional[str]
    severity: str = ""
    # filled in by the analysis
    verdict: str = ""
    scope: str = ""
    resolved_version: str = ""
    introduced_by: List[str] = field(default_factory=list)
    jar: str = ""
    reached_classes: int = 0
    total_classes: int = 0
    sample_path: List[str] = field(default_factory=list)
    hint_classes: List[str] = field(default_factory=list)
    hint_reached: List[str] = field(default_factory=list)
    autoconfigs: List[str] = field(default_factory=list)
    spi: List[str] = field(default_factory=list)
    config_mentions: List[str] = field(default_factory=list)
    osv: str = ""
    fixed_versions: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _norm(h: str) -> str:
    return re.sub(r"[^a-z]", "", (h or "").lower())


PKG_KEYS = ["packagename", "packageid", "library", "libraryname", "package", "component",
            "componentname", "dependency", "artifact", "name", "purl"]
VER_KEYS = ["packageversion", "libraryversion", "componentversion", "version"]
CVE_KEYS = ["cve", "cvename", "cveid", "vulnerabilityid", "vulnerability", "vulnid", "id"]
SEV_KEYS = ["severity", "risk", "risklevel"]


def split_package(pkg: str, version: Optional[str]) -> Tuple[Optional[str], str, Optional[str]]:
    """Accepts g:a, g:a:v, pkg:maven/g/a@v, 'Maven-g:a-1.2.3', or a bare artifactId."""
    p = pkg.strip()
    m = re.match(r"pkg:maven/([^/]+)/([^@?#]+)(?:@([^?#]+))?", p)
    if m:
        return m.group(1), m.group(2), version or m.group(3)
    p = re.sub(r"^(maven|mvn)[-:/ ]", "", p, flags=re.I)
    if version and p.endswith("-" + version):
        p = p[: -(len(version) + 1)]
    parts = p.split(":")
    if len(parts) >= 3:
        return parts[0], parts[1], version or parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], version
    # bare "activemq-client-5.18.2"?
    m = re.match(r"(.+?)-(\d+(?:\.\d+)+.*)$", p)
    if m and not version:
        return None, m.group(1), m.group(2)
    return None, p, version


def _pick(row: Dict[str, str], keys: List[str]) -> str:
    normed = {_norm(k): v for k, v in row.items() if k is not None}
    for k in keys:
        v = normed.get(k)
        if v not in (None, ""):
            return str(v).strip()
    return ""


def load_findings(path: Path) -> List[Finding]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    rows: List[Dict[str, str]] = []
    if path.suffix.lower() == ".json" or text.lstrip()[:1] in "[{":
        rows = list(_walk_json(json.loads(text), {}))
    else:
        sample = text[:4096]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(io.StringIO(text), dialect)
        all_rows = [r for r in reader if any(c.strip() for c in r)]
        if not all_rows:
            return []
        header = [_norm(h) for h in all_rows[0]]
        known = set(PKG_KEYS + VER_KEYS + CVE_KEYS + SEV_KEYS)
        if sum(h in known for h in header) >= 2:
            rows = [dict(zip(all_rows[0], r)) for r in all_rows[1:]]
        else:  # headerless: cve,package,version[,severity]
            rows = [dict(zip(["cve", "package", "version", "severity"], r)) for r in all_rows]

    out: Dict[Tuple[str, str, str], Finding] = {}
    for row in rows:
        cve = _pick(row, CVE_KEYS)
        m = CVE_RE.search(cve) or next((CVE_RE.search(str(v)) for v in row.values()
                                        if v and CVE_RE.search(str(v))), None)
        cve = m.group(1).upper() if m else cve
        pkg = _pick(row, PKG_KEYS)
        if not pkg or not cve:
            continue
        ver = _pick(row, VER_KEYS) or None
        g, a, v = split_package(pkg, ver)
        f = Finding(cve=cve, package=pkg, group=g, artifact=a, version=v,
                    severity=_pick(row, SEV_KEYS))
        out.setdefault((f.cve, f"{g}:{a}", v or ""), f)
    return list(out.values())


def _walk_json(node, ctx):
    """Yield flat dicts for every object that looks like a vulnerability. Package info
    found on a parent object (package -> vulnerabilities[]) is inherited by children."""
    if isinstance(node, list):
        for x in node:
            yield from _walk_json(x, ctx)
        return
    if not isinstance(node, dict):
        return
    flat = {k: v for k, v in node.items() if isinstance(v, (str, int, float))}
    local = dict(ctx)
    for keys in (PKG_KEYS, VER_KEYS):
        val = _pick(flat, keys)
        if val:
            for k in keys:
                local.pop(k, None)
            local[keys[0]] = val
    has_cve = any(CVE_RE.search(str(v)) for v in flat.values())
    if has_cve and (_pick(local, PKG_KEYS)):
        merged = dict(local)
        merged.update(flat)
        for keys in (PKG_KEYS, VER_KEYS):   # nearest package wins over our own "name"/"id"
            if _pick(local, keys):
                merged[keys[0]] = _pick(local, keys)
        yield merged
    for v in node.values():
        if isinstance(v, (dict, list)):
            yield from _walk_json(v, local)


# --------------------------------------------------------------------------- maven
@dataclass
class Node:
    group: str
    artifact: str
    version: str
    scope: str
    chain: List[str]                  # path of g:a:v from the project root


def find_mvn(project: Path) -> List[str]:
    for name in (["mvnw.cmd"] if os.name == "nt" else []) + ["mvnw"]:
        w = project / name
        if w.exists():
            return [str(w)]
    exe = shutil.which("mvn")
    if not exe:
        sys.exit("error: Maven not found (no ./mvnw and no mvn on PATH)")
    return [exe]


def run_mvn(project: Path, goal_args: List[str], extra: List[str]) -> None:
    cmd = find_mvn(project) + ["-B", "-q"] + extra + goal_args
    r = subprocess.run(cmd, cwd=project, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout[-4000:] + r.stderr[-4000:])
        sys.exit(f"error: Maven failed: {' '.join(cmd)}")


def parse_tree(text: str) -> List[Node]:
    """Parse `dependency:tree -DoutputType=text` output (possibly several modules)."""
    nodes: List[Node] = []
    stack: List[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.startswith("["):
            continue
        m = re.match(r"^([| ]*)(?:[+\\]- )?(.*)$", line)
        indent, coord = m.group(1), m.group(2).strip()
        coord = re.sub(r"\s*\(.*\)\s*$", "", coord)      # "(version managed from ...)" etc
        depth = 0 if not re.match(r"^[| ]*[+\\]- ", line) else len(indent) // 3 + 1
        parts = coord.split(":")
        if len(parts) < 4:
            continue
        g, a = parts[0], parts[1]
        if depth == 0:
            stack = [f"{g}:{a}:{parts[-1] if len(parts) == 4 else parts[3]}"]
            continue
        if len(parts) >= 6:
            v, scope = parts[-2], parts[-1]
        else:
            v, scope = parts[3], parts[4] if len(parts) > 4 else "compile"
        stack = stack[:depth]
        chain = stack[1:] + [f"{g}:{a}:{v}"]
        nodes.append(Node(g, a, v, scope, chain))
        stack.append(f"{g}:{a}:{v}")
    return nodes


def parse_list(text: str) -> Dict[Tuple[str, str], Tuple[str, str, str]]:
    """Parse `dependency:list -DoutputAbsoluteArtifactFilename=true` ->
    {(group, artifact): (version, scope, jar_path)}"""
    out = {}
    for raw in text.splitlines():
        line = re.sub(r"\s+--\s+module.*$", "", raw.strip())
        m = re.match(r"^(\S+?):((?:[A-Za-z]:)?[\\/].*)$", line)
        if not m:
            continue
        parts = m.group(1).split(":")
        if len(parts) < 5:
            continue
        g, a, scope = parts[0], parts[1], parts[-1]
        v = parts[-2]
        out[(g, a)] = (v, scope, m.group(2).strip())
    return out


# --------------------------------------------------------------------------- bytecode
def find_jdeps() -> str:
    jh = os.environ.get("JAVA_HOME")
    if jh:
        for n in ("jdeps", "jdeps.exe"):
            p = Path(jh) / "bin" / n
            if p.exists():
                return str(p)
    exe = shutil.which("jdeps")
    if not exe:
        sys.exit("error: jdeps not found - install a JDK 11+ or set JAVA_HOME")
    return exe


def list_classes(archive: Path) -> Set[str]:
    names = set()
    if archive.is_dir():
        for p in archive.rglob("*.class"):
            rel = p.relative_to(archive).as_posix()
            if rel != "module-info.class" and not rel.startswith("META-INF/"):
                names.add(rel[:-6].replace("/", "."))
        return names
    try:
        with zipfile.ZipFile(archive) as z:
            for n in z.namelist():
                if not n.endswith(".class") or n.endswith("module-info.class"):
                    continue
                n = re.sub(r"^META-INF/versions/\d+/", "", n)
                if n.startswith("META-INF/") or n.startswith("BOOT-INF/"):
                    continue
                names.add(n[:-6].replace("/", "."))
    except zipfile.BadZipFile:
        pass
    return names


EDGE_RE = re.compile(r"^\s+(\S+)\s+->\s+(\S+)\s")


def jdeps_edges(jdeps: str, archive: Path, cache_dir: Optional[Path]) -> List[Tuple[str, str]]:
    key = None
    if cache_dir and archive.is_file():
        st = archive.stat()
        key = hashlib.sha1(f"{archive.resolve()}|{st.st_size}|{st.st_mtime}".encode()).hexdigest()
        cf_ = cache_dir / f"{key}.json"
        if cf_.exists():
            try:
                return [tuple(e) for e in json.loads(cf_.read_text())]
            except (ValueError, OSError):
                pass
    cmd = [jdeps, "-verbose:class", "-filter:none", "--multi-release", "base", str(archive)]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    edges = []
    for line in r.stdout.splitlines():
        m = EDGE_RE.match(line)
        if m and m.group(1) != m.group(2):
            edges.append((m.group(1), m.group(2)))
    if key and (r.returncode == 0 or edges):
        try:
            (cache_dir / f"{key}.json").write_text(json.dumps(edges))
        except OSError:
            pass
    return edges


def reachability(roots: Iterable[str], graph: Dict[str, Set[str]]) -> Dict[str, Optional[str]]:
    """BFS; returns {reached_class: parent_class}."""
    parent: Dict[str, Optional[str]] = {}
    q = deque()
    for r in roots:
        parent[r] = None
        q.append(r)
    while q:
        c = q.popleft()
        for t in graph.get(c, ()):
            if t not in parent:
                parent[t] = c
                q.append(t)
    return parent


def path_to(cls: str, parent: Dict[str, Optional[str]]) -> List[str]:
    out = []
    while cls is not None and len(out) < 50:
        out.append(cls)
        cls = parent.get(cls)
    return list(reversed(out))


# --------------------------------------------------------------------------- spring
AUTOCONF_IMPORTS = "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"


def _read_entry(archive: Path, name: str) -> Optional[str]:
    try:
        if archive.is_dir():
            p = archive / name
            return p.read_text(errors="replace") if p.is_file() else None
        with zipfile.ZipFile(archive) as z:
            return z.read(name).decode("utf-8", "replace") if name in z.namelist() else None
    except (zipfile.BadZipFile, OSError, KeyError):
        return None


def _names(archive: Path) -> List[str]:
    if archive.is_dir():
        return [p.relative_to(archive).as_posix() for p in archive.rglob("*") if p.is_file()]
    try:
        with zipfile.ZipFile(archive) as z:
            return z.namelist()
    except (zipfile.BadZipFile, OSError):
        return []


def entry_points(archive: Path) -> List[Tuple[str, str]]:
    """Classes a framework may instantiate without a static reference from your code:
    [(class, kind)] with kind in {"auto-config", "spring.factories", "ServiceLoader"}."""
    out: List[Tuple[str, str]] = []
    txt = _read_entry(archive, AUTOCONF_IMPORTS)
    if txt:
        for l in txt.splitlines():
            l = l.split("#", 1)[0].strip()
            if l:
                out.append((l, "auto-config"))
    txt = _read_entry(archive, "META-INF/spring.factories")
    if txt:
        txt = re.sub(r"\\\r?\n", "", txt)
        for l in txt.splitlines():
            if "=" not in l or l.strip().startswith("#"):
                continue
            k, v = l.split("=", 1)
            kind = "auto-config" if k.strip().endswith("EnableAutoConfiguration") else "spring.factories"
            out += [(c.strip(), kind) for c in v.split(",") if c.strip()]
    for n in _names(archive):
        if n.startswith("META-INF/services/") and not n.endswith("/"):
            for l in (_read_entry(archive, n) or "").splitlines():
                l = l.split("#", 1)[0].strip()
                if l:
                    out.append((l, "ServiceLoader"))
    return out


def autoconfig_refs(jar: Path, classes: List[str], packages: Set[str]) -> Dict[str, Set[str]]:
    """{autoconfig_class: {vulnerable packages whose names appear in its bytecode}}.
    Byte search catches @ConditionalOnClass(X.class) and string class names, which
    jdeps doesn't report."""
    out: Dict[str, Set[str]] = {}
    needles = [(p, ("L" + p.replace(".", "/") + "/").encode(), (p + ".").encode(),
                (p.replace(".", "/") + "/").encode()) for p in packages]
    try:
        with zipfile.ZipFile(jar) as z:
            names = z.namelist()
            for ac in classes:
                base = ac.replace(".", "/")
                blobs = [z.read(n) for n in names
                         if n == base + ".class" or (n.startswith(base + "$") and n.endswith(".class"))]
                hits = {p for p, n1, n2, n3 in needles for b in blobs if n1 in b or n2 in b or n3 in b}
                if hits:
                    out[ac] = hits
    except (zipfile.BadZipFile, OSError):
        pass
    return out


def spi_services(jar: Path) -> List[str]:
    try:
        with zipfile.ZipFile(jar) as z:
            return sorted(n[len("META-INF/services/"):] for n in z.namelist()
                          if n.startswith("META-INF/services/") and not n.endswith("/"))
    except (zipfile.BadZipFile, OSError):
        return []


def config_files(project: Path) -> List[Path]:
    files = []
    for base in [project / "src" / "main" / "resources", project / "config", project]:
        if base.is_dir():
            for p in base.iterdir():
                if re.match(r"^(application|bootstrap)[\w.-]*\.(ya?ml|properties)$", p.name):
                    files.append(p)
    return files


def excluded_autoconfigs(project: Path) -> Set[str]:
    """Simple names of auto-configurations excluded via spring.autoconfigure.exclude or
    @SpringBootApplication/@EnableAutoConfiguration(exclude = ...)."""
    names: Set[str] = set()
    for p in config_files(project):          # config files rarely name auto-configs otherwise
        names.update(re.findall(r"(\w+AutoConfiguration)\b", p.read_text(errors="replace")))
    src = project / "src" / "main"
    if src.is_dir():
        for p in list(src.rglob("*.java")) + list(src.rglob("*.kt")):
            t = p.read_text(errors="replace")
            for m in re.finditer(r"exclude(?:Name)?\s*=\s*(\{[^}]*\}|\[[^\]]*\]|[^,)]+)", t):
                names.update(re.findall(r"(\w+AutoConfiguration)\b", m.group(1)))
    return names


def keyword_for(artifact: str) -> Optional[str]:
    for tok in re.split(r"[-_.]", artifact.lower()):
        if len(tok) > 3 and tok not in GENERIC_TOKENS and not tok.isdigit():
            return tok
    return None


def config_mentions(project: Path, keyword: Optional[str]) -> List[str]:
    if not keyword:
        return []
    out = []
    for p in config_files(project):
        for i, l in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if keyword in l.lower() and not l.strip().startswith("#"):
                out.append(f"{p.name}:{i}: {l.strip()[:100]}")
    return out[:8]


# --------------------------------------------------------------------------- OSV
def osv_check(f: Finding, timeout: float = 20) -> None:
    body = json.dumps({"package": {"ecosystem": "Maven", "name": f"{f.group}:{f.artifact}"},
                       "version": f.resolved_version}).encode()
    try:
        req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:                                    # noqa: BLE001
        f.osv = f"lookup failed ({e.__class__.__name__})"
        return
    for v in data.get("vulns", []):
        ids = {v.get("id", "").upper()} | {a.upper() for a in v.get("aliases", [])}
        if f.cve.upper() in ids:
            fixed = set()
            for aff in v.get("affected", []):
                if aff.get("package", {}).get("name") != f"{f.group}:{f.artifact}":
                    continue
                for rng in aff.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed.add(ev["fixed"])
            f.osv = f"affected ({v.get('id')})"
            f.fixed_versions = sorted(fixed, key=_vkey)
            return
    f.osv = "not affected"


def _vkey(v: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"[.\-]", v)]



# --------------------------------------------------------------------------- built-in guides
HOW_TO_EXPORT = """
HOW TO EXPORT YOUR FINDINGS FROM CHECKMARX
==========================================
cx_reach.py needs the list of vulnerable packages (SCA results) as CSV or JSON.
Menu names differ a little between Checkmarx versions; use whichever matches yours.

Checkmarx One (web UI)
  1. Open your project -> pick the latest scan.
  2. Go to the SCA results (tab "SCA" / "Open Source" / "Vulnerabilities").
  3. Use "Export" (or "Download report") and choose CSV or JSON.
     If you're offered a scan report instead, pick JSON and include SCA results.

Checkmarx One CLI ("cx")
  cx scan create --project-name <name> -s . --branch <branch> --scan-types sca
  cx results show --scan-id <SCAN_ID> --report-format json --output-name cx-results --output-path .
  (The first command prints the scan ID. If a flag is rejected: cx results show --help)

Checkmarx SCA (standalone, older) / CxSAST with SCA
  Open the project -> latest scan -> "Export" / "Reports" -> CSV or JSON of
  vulnerabilities/packages.

No export rights? Ask your AppSec team for the SCA results "as CSV", or write
the file yourself, one finding per line:

  Package Name,Package Version,CVE
  org.apache.activemq:activemq-client,5.18.2,CVE-2023-46604

Then run:
  python cx_reach.py <export file> -p <path to your Spring Boot module>

If the script says "no findings recognised", send the first lines of the export
(column names + one row) to whoever maintains this script: the parser only needs
to learn your column names.
"""

EXPLAIN_HINTS = """
WHAT IS hints.example.json?
===========================
Checkmarx tells you a LIBRARY is vulnerable, but a CVE usually lives in one
small part of that library. A hint tells cx_reach.py which classes contain the
vulnerable code, so it can answer "is the vulnerable part reachable?" instead
of just "is the library used?".

Format (one entry per CVE):

  {
    "CVE-2023-46604": {
      "classes": ["org.apache.activemq.openwire"],
      "note": "OpenWire unmarshalling"
    }
  }

  classes  class names or package prefixes. "org.apache.activemq.openwire"
           matches every class in that package and its sub-packages.
  note     optional; copied into the report so reviewers see why.
  Keys starting with "_" (like "_comment") are ignored.

What changes when you use it (--hints hints.json):
  without hint:  library used by your code                 -> USED
  with hint:     vulnerable classes reachable from your code -> REACHABLE (fix first)
                 library used, vulnerable classes not reached -> USED-SAFE?

Where to find the class names for your own criticals:
  - The advisory: GitHub Security Advisories (github.com/advisories), NVD,
    the project's security page. They often name the class or method.
  - The fix commit linked from the advisory: the files it changes are the
    vulnerable classes.
  - The Checkmarx finding details sometimes mention the affected method.

Start with a template for exactly your findings:
  python cx_reach.py <export file> --make-hints my-hints.json
then fill in "classes" for the criticals you care about (leave the rest empty).

Caveat: this is class-level. "Reachable" means your code can get to that
class, not that attacker input reaches the vulnerable method. USED-SAFE? is
strong evidence, not proof; check the CVE's preconditions before closing it.
"""


def make_hints(findings: List[Finding], out: Path) -> None:
    data = {"_comment": "Fill in 'classes' with the vulnerable class/package names from each "
                        "advisory (run: python cx_reach.py --explain-hints). Empty entries are ignored."}
    for f in sorted(findings, key=lambda f: f.cve):
        data.setdefault(f.cve, {
            "classes": [],
            "note": f"{f.group + ':' if f.group else ''}{f.artifact} {f.version or ''}".strip(),
            "advisory": f"https://github.com/advisories?query={f.cve}",
            "nvd": f"https://nvd.nist.gov/vuln/detail/{f.cve}",
        })
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_report(path: Optional[str]) -> List[Finding]:
    if not path or not Path(path).is_file():
        print(HOW_TO_EXPORT)
        sys.exit(f"error: Checkmarx export not found: {path or '(none given)'}")
    findings = load_findings(Path(path))
    if not findings:
        print(HOW_TO_EXPORT)
        sys.exit("error: no findings recognised in the report "
                 "(expected columns like CVE / Package Name / Package Version)")
    return findings


# --------------------------------------------------------------------------- main analysis
def analyse(args) -> List[Finding]:
    findings = read_report(args.report)
    project = Path(args.project).resolve()
    if not (project / "pom.xml").exists():
        sys.exit(f"error: no pom.xml in {project}")
    pom = (project / "pom.xml").read_text(errors="replace")
    if "<modules>" in pom and not args.classes:
        sys.exit("error: this is a multi-module parent POM. Run the script on the module that "
                 "builds the application (e.g. --project app-module) after "
                 "`mvn install -DskipTests` at the root, or pass --classes.")

    log(f"{len(findings)} finding(s) loaded from {args.report}")

    work = Path(tempfile.mkdtemp(prefix="cx-reach-"))
    extra = args.mvn_arg or []

    # 1. dependency tree + resolved jars
    tree_file = Path(args.tree_file) if args.tree_file else work / "tree.txt"
    list_file = Path(args.list_file) if args.list_file else work / "list.txt"
    if not args.tree_file:
        log("resolving dependency tree (mvn dependency:tree)...")
        run_mvn(project, [f"{DEP_PLUGIN}:tree", f"-DoutputFile={tree_file}",
                          "-DoutputType=text"], extra)
    if not args.list_file:
        log("resolving jar locations (mvn dependency:list)...")
        run_mvn(project, [f"{DEP_PLUGIN}:list", f"-DoutputFile={list_file}",
                          "-DoutputAbsoluteArtifactFilename=true"], extra)
    nodes = parse_tree(tree_file.read_text(errors="replace"))
    resolved = parse_list(list_file.read_text(errors="replace"))

    # 2. compiled classes
    classes_dir = Path(args.classes) if args.classes else project / "target" / "classes"
    if args.build or not classes_dir.is_dir():
        log("compiling project (mvn compile -DskipTests)...")
        run_mvn(project, ["-DskipTests", "compile"], extra)
    if not classes_dir.is_dir():
        sys.exit(f"error: compiled classes not found at {classes_dir}")

    runtime_jars = {ga: Path(p) for ga, (v, s, p) in resolved.items()
                    if s in RUNTIME_SCOPES and p.endswith(".jar") and Path(p).exists()}

    # 3. class graph
    jdeps = find_jdeps()
    cache = None if args.no_cache else Path.home() / ".cache" / "cx-reach"
    if cache:
        cache.mkdir(parents=True, exist_ok=True)
    archives = [classes_dir] + list(runtime_jars.values())
    log(f"analysing bytecode of {len(archives)} archives with jdeps...")
    graph: Dict[str, Set[str]] = {}
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for edges in ex.map(lambda a: jdeps_edges(jdeps, a, cache), archives):
            for s, t in edges:
                graph.setdefault(s, set()).add(t)

    app_classes = list_classes(classes_dir)
    reached = reachability(app_classes, graph)
    log(f"{len(app_classes)} classes of yours reference {len(reached) - len(app_classes)} other classes (transitively)")

    # Things Spring Boot / the JVM instantiate by name, without a static reference from you.
    excluded = excluded_autoconfigs(project)
    ac_roots, fw_roots, services = {}, {}, []
    for arch in archives:
        for c, kind in entry_points(arch):
            if kind == "auto-config":
                if c.rsplit(".", 1)[-1] in excluded:
                    continue
                ac_roots[c] = arch
            elif kind == "spring.factories":
                fw_roots[c] = kind
            else:
                services.append((arch, c))
    fw_pre = reachability(fw_roots, graph)
    # A ServiceLoader provider only loads if someone asks for that service interface.
    svc_roots = {}
    for arch in archives:
        for n in _names(arch):
            if n.startswith("META-INF/services/") and not n.endswith("/"):
                iface = n[len("META-INF/services/"):]
                if iface.startswith(("java.", "javax.")) or iface in reached or iface in fw_pre:
                    for l in (_read_entry(arch, n) or "").splitlines():
                        l = l.split("#", 1)[0].strip()
                        if l:
                            svc_roots[l] = "ServiceLoader"
    reached_fw = reachability(list(fw_roots) + list(svc_roots), graph)
    reached_ac = reachability(ac_roots, graph)
    log(f"{len(ac_roots)} auto-configs, {len(fw_roots)} spring.factories and "
        f"{len(svc_roots)} ServiceLoader entry points")

    hints = json.loads(Path(args.hints).read_text()) if args.hints else {}
    hints = {k.upper(): v for k, v in hints.items()
             if not k.startswith("_") and isinstance(v, dict) and v.get("classes")}
    ac_jars = {}
    for c, arch in ac_roots.items():
        ac_jars.setdefault(arch, []).append(c)
    jar_classes_cache: Dict[Path, Set[str]] = {}

    def is_hinted(c: str, prefixes: List[str]) -> bool:
        return any(c == p or c.startswith(p + ".") or c.startswith(p + "$") for p in prefixes)

    # 4. evaluate every finding
    for f in findings:
        in_tree = [n for n in nodes if n.artifact == f.artifact and (not f.group or n.group == f.group)]
        if in_tree:
            f.group = f.group or in_tree[0].group
            f.introduced_by = sorted({n.chain[0] for n in in_tree})
            f.scope = ",".join(sorted({n.scope for n in in_tree}))
            f.resolved_version = in_tree[0].version
        key = (f.group, f.artifact)
        if key in resolved:
            f.resolved_version, s, jar = resolved[key]
            f.scope = s
            f.jar = jar
        if not in_tree and key not in resolved:
            f.verdict = "NOT-FOUND"
            continue
        if f.version and f.resolved_version and f.version != f.resolved_version:
            f.notes.append(f"report says {f.version}, project resolves {f.resolved_version}")
        if args.osv and f.group:
            osv_check(f)
        if f.scope and not (set(f.scope.split(",")) & RUNTIME_SCOPES):
            f.verdict = "NOT-SHIPPED"
            continue
        if f.osv == "not affected":
            f.verdict = "NOT-AFFECTED"
            continue
        jar = runtime_jars.get(key)
        if not jar:
            f.verdict = "NOT-FOUND"
            f.notes.append("in dependency tree but jar not resolved locally")
            continue
        cls = jar_classes_cache.setdefault(jar, list_classes(jar))
        f.total_classes = len(cls)
        prefixes = hints.get(f.cve.upper(), {}).get("classes", [])
        f.hint_classes = prefixes
        if hints.get(f.cve.upper(), {}).get("note"):
            f.notes.append("hint: " + hints[f.cve.upper()]["note"])

        def best(reach):
            hit = sorted(c for c in cls if c in reach)
            hinted = [c for c in hit if prefixes and is_hinted(c, prefixes)]
            return hit, hinted, (path_to((hinted or hit)[0], reach) if hit else [])

        hit, hinted, path = best(reached)
        f.reached_classes, f.hint_reached = len(hit), hinted
        if hit:
            f.sample_path = path
        f.config_mentions = config_mentions(project, keyword_for(f.artifact))

        if hinted:
            f.verdict = "REACHABLE"
            continue
        if hit:
            f.verdict = "USED-SAFE?" if prefixes else "USED"
            continue

        # no static path from your code - can the framework load it?
        packages = {c.rsplit(".", 1)[0] for c in cls if "." in c}
        ac_hit, ac_hinted, ac_path = best(reached_ac)
        acs = set()
        if ac_hit:
            acs.add(ac_path[0])
        for aj, acl in ac_jars.items():
            if aj.is_file():
                acs.update(autoconfig_refs(aj, acl, packages))
        fw_hit, fw_hinted, fw_path = best(reached_fw)
        f.autoconfigs = sorted(acs)
        if ac_hinted or fw_hinted:
            f.notes.append("hinted vulnerable classes are reachable through the framework path")
        if f.autoconfigs:
            f.verdict = "AUTOCONFIG"
            f.sample_path = ac_path
        elif fw_hit:
            f.verdict = "FRAMEWORK"
            f.sample_path = fw_path
            f.spi = [fw_path[0]]
        else:
            f.verdict = "UNUSED"
            f.spi = spi_services(jar)
            if f.spi:
                f.notes.append("jar registers ServiceLoader services, but nothing on the "
                               "classpath appears to request them")
    shutil.rmtree(work, ignore_errors=True)
    return findings


# --------------------------------------------------------------------------- output
ORDER = ["REACHABLE", "USED", "USED-SAFE?", "AUTOCONFIG", "FRAMEWORK", "UNUSED",
         "NOT-SHIPPED", "NOT-AFFECTED", "NOT-FOUND"]
ADVICE = {
    "REACHABLE": "Vulnerable classes are reachable from your code. Upgrade now.",
    "USED": "Library is used by your code. Upgrade (or pin a fixed version) and review the CVE conditions.",
    "USED-SAFE?": "Library is used, but not the hinted vulnerable classes. Likely not exploitable - confirm, then mark in Checkmarx with this evidence.",
    "AUTOCONFIG": "Spring Boot auto-configuration uses it and activates when it is on the classpath (unless its conditions fail). Exclude the library or the auto-config if you don't need it, otherwise upgrade.",
    "FRAMEWORK": "Your code doesn't reference it, but Spring (spring.factories) or a ServiceLoader lookup loads code that does. Treat as used.",
    "UNUSED": "Nothing references it. Exclude it from the dependency that brings it in and re-run your tests.",
    "NOT-SHIPPED": "Only test/provided scope - not part of the deployed app.",
    "NOT-AFFECTED": "OSV says the resolved version is not affected.",
    "NOT-FOUND": "Not in the resolved tree - probably already upgraded/removed, or the report uses another name.",
}


def ga_of(coord: str) -> Tuple[str, str]:
    p = coord.split(":")
    return p[0], p[1]


def exclusion_snippet(f: Finding) -> str:
    out = []
    for coord in f.introduced_by:
        g, a = ga_of(coord)
        if (g, a) == (f.group, f.artifact):
            continue
        out.append(f"""<dependency>
  <groupId>{g}</groupId>
  <artifactId>{a}</artifactId>
  <exclusions>
    <exclusion>
      <groupId>{f.group}</groupId>
      <artifactId>{f.artifact}</artifactId>
    </exclusion>
  </exclusions>
</dependency>""")
    return "\n".join(out)


def pin_snippet(f: Finding) -> str:
    ver = fix_version(f) or "FIXED_VERSION"
    return f"""<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>{f.group}</groupId>
      <artifactId>{f.artifact}</artifactId>
      <version>{ver}</version>
    </dependency>
  </dependencies>
</dependencyManagement>"""


def fix_version(f: Finding) -> Optional[str]:
    if not f.fixed_versions:
        return None
    ver = f.fixed_versions[-1]
    for fv in f.fixed_versions:              # prefer the fix in the same major line
        if fv.split(".")[0] == (f.resolved_version or "").split(".")[0]:
            ver = fv
    return ver


def build_plan(findings: List[Finding]) -> dict:
    """Merge all findings into one set of pom.xml changes, per library."""
    libs: Dict[Tuple[str, str], List[Finding]] = {}
    for f in findings:
        if f.group:
            libs.setdefault((f.group, f.artifact), []).append(f)
    remove, exclude, upgrade, decide, nothing = [], {}, [], [], []
    for ga, fs in sorted(libs.items()):
        verdicts = {f.verdict for f in fs}
        cves = sorted({f.cve for f in fs})
        f0 = fs[0]
        worst = min(verdicts, key=ORDER.index)
        entry = {"group": ga[0], "artifact": ga[1], "version": f0.resolved_version,
                 "cves": cves, "verdict": worst, "introduced_by": f0.introduced_by}
        if worst in ("REACHABLE", "USED", "USED-SAFE?", "FRAMEWORK"):
            vers = [v for v in (fix_version(f) for f in fs) if v]
            entry["fixed"] = max(vers, key=_vkey) if vers else None
            upgrade.append(entry)
        elif worst == "AUTOCONFIG":
            vers = [v for v in (fix_version(f) for f in fs) if v]
            entry["fixed"] = max(vers, key=_vkey) if vers else None
            decide.append(entry)
        elif worst == "UNUSED":
            if any(ga_of(c) == ga for c in f0.introduced_by):
                remove.append(entry)
            for c in f0.introduced_by:
                if ga_of(c) != ga:
                    exclude.setdefault(ga_of(c), []).append(entry)
        else:
            nothing.append(entry)
    removed = {(e["group"], e["artifact"]) for e in remove}
    # no need to add exclusions to a dependency we're deleting anyway: it takes them with it
    for e in remove:
        e["takes_with"] = [x for x in exclude.get((e["group"], e["artifact"]), [])]
    exclude = {k: v for k, v in exclude.items() if k not in removed}
    # a library whose every introducer gets deleted disappears on its own
    return {"remove": remove, "exclude": exclude, "upgrade": upgrade,
            "decide": decide, "nothing": nothing, "removed": removed}


def render_plan_md(plan: dict) -> List[str]:
    L = ["## Action plan", ""]
    n = 0
    if plan["remove"]:
        n += 1
        L += [f"### {n}. Delete these dependencies from pom.xml (nothing uses them)", ""]
        for e in plan["remove"]:
            gone = e.get("takes_with") or []
            also = ", ".join("`%s` (%s)" % (x["artifact"], ", ".join(x["cves"])) for x in gone)
            L.append(f"- `{e['group']}:{e['artifact']}` ({', '.join(e['cves'])})"
                     + (f"; this also removes {also}" if gone else ""))
        L.append("")
    if plan["exclude"]:
        n += 1
        L += [f"### {n}. Add exclusions (transitive libraries nothing uses)", "",
              "| Add to dependency | Exclude | Clears |", "|---|---|---|"]
        for (g, a), es in sorted(plan["exclude"].items()):
            for e in es:
                L.append(f"| `{g}:{a}` | `{e['group']}:{e['artifact']}` | {', '.join(e['cves'])} |")
        L.append("")
    if plan["upgrade"]:
        n += 1
        L += [f"### {n}. Upgrade (still used, can't be excluded)", "",
              "| Library | Now | Fix version | Why it stays | Clears |", "|---|---|---|---|---|"]
        for e in plan["upgrade"]:
            L.append(f"| `{e['group']}:{e['artifact']}` | {e['version']} | "
                     f"{e['fixed'] or 'see advisory (run with --osv)'} | {e['verdict']} | {', '.join(e['cves'])} |")
        L.append("")
    if plan["decide"]:
        n += 1
        L += [f"### {n}. Your call: exclude if you don't use the feature, otherwise upgrade", "",
              "Spring Boot auto-configures these just because they're on the classpath. "
              "If the app doesn't use the feature, remove the starter that brings it in "
              "(and its settings in application.yml). If it does, upgrade.", ""]
        for e in plan["decide"]:
            L.append(f"- `{e['group']}:{e['artifact']}` {e['version']} ({', '.join(e['cves'])}), "
                     f"brought in by {', '.join(f'`{c}`' for c in e['introduced_by'])}"
                     + (f"; fix version {e['fixed']}" if e["fixed"] else ""))
        L.append("")
    if plan["nothing"]:
        n += 1
        L += [f"### {n}. Nothing to change in the pom", ""]
        for e in plan["nothing"]:
            L.append(f"- `{e['group']}:{e['artifact']}` ({', '.join(e['cves'])}): {e['verdict']}")
        L.append("")
    L += ["After changing the pom: `mvn dependency:tree` to confirm, `mvn test`, start the app, "
          "then rescan with Checkmarx.", ""]
    return L


def render_pom_changes(plan: dict) -> str:
    out = ["<!-- Generated by cx_reach.py. Review before pasting into pom.xml. -->", ""]
    if plan["remove"]:
        out.append("<!-- 1. DELETE these <dependency> blocks from pom.xml:")
        for e in plan["remove"]:
            out.append(f"       {e['group']}:{e['artifact']}   ({', '.join(e['cves'])})")
            for x in e.get("takes_with") or []:
                out.append(f"         (also removes {x['group']}:{x['artifact']}, {', '.join(x['cves'])})")
        out += ["-->", ""]
    if plan["exclude"]:
        out.append("<!-- 2. EXCLUSIONS: merge these into the existing <dependency> blocks "
                   "(keep their <version>/<scope> if they have one) -->")
        for (g, a), es in sorted(plan["exclude"].items()):
            out += ["<dependency>", f"  <groupId>{g}</groupId>", f"  <artifactId>{a}</artifactId>",
                    "  <exclusions>"]
            for e in es:
                out += [f"    <!-- {', '.join(e['cves'])} -->", "    <exclusion>",
                        f"      <groupId>{e['group']}</groupId>",
                        f"      <artifactId>{e['artifact']}</artifactId>", "    </exclusion>"]
            out += ["  </exclusions>", "</dependency>", ""]
    ups = plan["upgrade"] + [dict(e, _decide=True) for e in plan["decide"]]
    if ups:
        out += ["<!-- 3. UPGRADES: add to <dependencyManagement>. With the Spring Boot parent you can",
                "     usually set its version property instead, e.g. <snakeyaml.version>. -->",
                "<dependencyManagement>", "  <dependencies>"]
        for e in ups:
            note = ", only if you keep it (see action plan)" if e.get("_decide") else ""
            out += [f"    <!-- {', '.join(e['cves'])}: {e['version']} -> fixed{note} -->",
                    "    <dependency>", f"      <groupId>{e['group']}</groupId>",
                    f"      <artifactId>{e['artifact']}</artifactId>",
                    f"      <version>{e['fixed'] or 'FIXED_VERSION'}</version>", "    </dependency>"]
        out += ["  </dependencies>", "</dependencyManagement>", ""]
    return "\n".join(out)


def short(cls: str) -> str:
    return cls if len(cls) < 70 else "..." + cls[-67:]


def render_markdown(findings: List[Finding], project: str) -> str:
    fs = sorted(findings, key=lambda f: (ORDER.index(f.verdict), f.cve))
    lines = [f"# Checkmarx reachability report", "", f"Project: `{project}`", ""]
    lines += render_plan_md(build_plan(findings))
    lines += ["## All findings", "",
              "| Verdict | CVE | Library | Resolved | Brought in by |", "|---|---|---|---|---|"]
    for f in fs:
        lines.append(f"| **{f.verdict}** | {f.cve} | {f.group or '?'}:{f.artifact} | "
                     f"{f.resolved_version or '-'} ({f.scope or '-'}) | "
                     f"{', '.join(f.introduced_by) or '-'} |")
    for f in fs:
        lines += ["", f"### {f.verdict} - {f.cve} in {f.artifact} {f.resolved_version}", "",
                  ADVICE[f.verdict], ""]
        if f.severity:
            lines.append(f"- Severity (Checkmarx): {f.severity}")
        if f.introduced_by:
            lines.append(f"- Brought in by: {', '.join(f'`{c}`' for c in f.introduced_by)}")
        if f.total_classes:
            lines.append(f"- Classes reached from your code: {f.reached_classes} of {f.total_classes}")
        if f.hint_classes:
            lines.append(f"- Hinted vulnerable classes: {', '.join(f.hint_classes)} -> "
                         f"{'reached from your code: ' + ', '.join(f.hint_reached[:5]) if f.hint_reached else 'not reached from your code'}")
        if f.sample_path:
            lines += ["- Example path:", "  ```"] + [f"  {'  ' * i}-> {c}" if i else f"  {c}"
                                                     for i, c in enumerate(f.sample_path)] + ["  ```"]
        if f.autoconfigs:
            lines.append(f"- Spring Boot auto-configs referencing it: {', '.join(a.rsplit('.', 1)[-1] for a in f.autoconfigs[:6])}")
        if f.spi and f.verdict == "UNUSED":
            lines.append(f"- ServiceLoader registrations: {', '.join(f.spi[:5])}")
        if f.config_mentions:
            lines.append("- Mentioned in your config: " + "; ".join(f"`{m}`" for m in f.config_mentions[:4]))
        if f.osv:
            lines.append(f"- OSV: {f.osv}" + (f"; fixed in {', '.join(f.fixed_versions)}" if f.fixed_versions else ""))
        for n in f.notes:
            lines.append(f"- Note: {n}")
        direct = any(ga_of(c) == (f.group, f.artifact) for c in f.introduced_by)
        if f.verdict in ("UNUSED", "AUTOCONFIG") and direct:
            lines += ["", f"`{f.artifact}` is declared directly in your pom.xml: if you don't "
                          "need it, delete that `<dependency>` block."]
        if f.verdict in ("UNUSED", "AUTOCONFIG") and exclusion_snippet(f):
            lines += ["", "Exclusion (pom.xml):", "```xml", exclusion_snippet(f), "```"]
        if f.verdict in ("REACHABLE", "USED", "USED-SAFE?", "AUTOCONFIG", "FRAMEWORK"):
            lines += ["", "Pin a fixed version (pom.xml; with the Spring Boot parent you can "
                          "often just override its version property instead):",
                      "```xml", pin_snippet(f), "```"]
    return "\n".join(lines) + "\n"


def print_summary(findings: List[Finding]) -> None:
    fs = sorted(findings, key=lambda f: (ORDER.index(f.verdict), f.cve))
    w = max(len(f.artifact) for f in fs) + 2
    print()
    print(f"{'VERDICT':<13}{'CVE':<17}{'LIBRARY':<{w}}{'VERSION':<12}DETAIL")
    print("-" * (13 + 17 + w + 12 + 40))
    for f in fs:
        if f.hint_reached:
            detail = f"vuln class reached: {short(f.hint_reached[0])}"
        elif f.reached_classes:
            detail = f"{f.reached_classes}/{f.total_classes} classes reached"
        elif f.autoconfigs:
            detail = "auto-config: " + ", ".join(a.rsplit('.', 1)[-1] for a in f.autoconfigs[:2])
        elif f.verdict == "FRAMEWORK" and f.sample_path:
            detail = "loaded via " + short(f.sample_path[0])
        elif f.introduced_by:
            detail = "via " + ", ".join(ga_of(c)[1] for c in f.introduced_by)
        else:
            detail = ""
        if f.config_mentions:
            detail += "  [in config]"
        print(f"{f.verdict:<13}{f.cve:<17}{f.artifact:<{w}}{(f.resolved_version or '-'):<12}{detail}")
    print()


def print_plan(plan: dict) -> None:
    print("WHAT TO DO")
    for e in plan["remove"]:
        gone = ", ".join(x["artifact"] for x in e.get("takes_with") or [])
        print(f"  delete dependency   {e['group']}:{e['artifact']}" + (f"  (also removes {gone})" if gone else ""))
    for (g, a), es in sorted(plan["exclude"].items()):
        for e in es:
            print(f"  exclude             {e['group']}:{e['artifact']}  from {g}:{a}")
    for e in plan["upgrade"]:
        print(f"  upgrade             {e['group']}:{e['artifact']} {e['version']} -> {e['fixed'] or '?'}")
    for e in plan["decide"]:
        print(f"  remove or upgrade   {e['group']}:{e['artifact']} (Spring auto-config; is the feature used?)")
    if not any(plan[k] for k in ("remove", "exclude", "upgrade", "decide")):
        print("  nothing - no findings need a pom change")
    print()


def log(msg: str) -> None:
    print(f"[cx-reach] {msg}", file=sys.stderr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Example: python cx_reach.py checkmarx.csv -p ~/work/my-service --osv\n"
                                        "First time? python cx_reach.py --how-to-export")
    ap.add_argument("report", nargs="?", help="Checkmarx export (CSV or JSON); see --how-to-export")
    ap.add_argument("--how-to-export", action="store_true", help="explain how to export findings from Checkmarx")
    ap.add_argument("--explain-hints", action="store_true", help="explain the hints file and how to fill it")
    ap.add_argument("--make-hints", metavar="FILE", help="write a hints template for the CVEs in the report, then exit")
    ap.add_argument("-p", "--project", default=".", help="Maven project dir (default: .)")
    ap.add_argument("--hints", help="JSON: {CVE: {\"classes\": [vulnerable class/package prefixes]}}")
    ap.add_argument("--osv", action="store_true", help="check affected/fixed versions on osv.dev")
    ap.add_argument("--build", action="store_true", help="always run mvn compile first")
    ap.add_argument("--classes", help="compiled classes dir (default: <project>/target/classes)")
    ap.add_argument("--tree-file", help="use an existing `dependency:tree -DoutputType=text` output")
    ap.add_argument("--list-file", help="use an existing `dependency:list -DoutputAbsoluteArtifactFilename=true` output")
    ap.add_argument("--mvn-arg", action="append", help="extra Maven arg, repeatable (e.g. -s settings.xml -P prod)")
    ap.add_argument("-o", "--out", default="cx-reach-report", help="report base name (.md and .json written)")
    ap.add_argument("-j", "--jobs", type=int, default=min(8, os.cpu_count() or 2))
    ap.add_argument("--no-cache", action="store_true", help="don't cache jdeps results in ~/.cache/cx-reach")
    ap.add_argument("--fail-on", choices=["reachable", "used", "autoconfig", "never"], default="never",
                    help="exit 1 if any finding is at or above this level (for CI)")
    args = ap.parse_args(argv)
    if args.how_to_export:
        print(HOW_TO_EXPORT)
        return 0
    if args.explain_hints:
        print(EXPLAIN_HINTS)
        return 0
    if args.make_hints:
        fs = read_report(args.report)
        make_hints(fs, Path(args.make_hints))
        print(f"wrote {args.make_hints} with {len({f.cve for f in fs})} CVE(s). Fill in 'classes' "
              f"for the ones that matter, then run with --hints {args.make_hints}.\n"
              f"How to find the class names: python cx_reach.py --explain-hints")
        return 0

    findings = analyse(args)
    print_summary(findings)
    Path(args.out + ".md").write_text(render_markdown(findings, str(Path(args.project).resolve())),
                                      encoding="utf-8")
    Path(args.out + ".json").write_text(json.dumps([f.__dict__ for f in findings], indent=2),
                                        encoding="utf-8")
    plan = build_plan(findings)
    Path(args.out + "-pom-changes.xml").write_text(render_pom_changes(plan), encoding="utf-8")
    print_plan(plan)
    if not args.hints and any(f.verdict in ("USED", "FRAMEWORK", "AUTOCONFIG") for f in findings):
        log("tip: --hints tells USED apart from REACHABLE (see: python cx_reach.py --explain-hints)")
    log(f"report written to {args.out}.md, {args.out}.json and {args.out}-pom-changes.xml")

    levels = {"reachable": ["REACHABLE"], "used": ["REACHABLE", "USED"],
              "autoconfig": ["REACHABLE", "USED", "USED-SAFE?", "AUTOCONFIG", "FRAMEWORK"], "never": []}
    return 1 if any(f.verdict in levels[args.fail_on] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
