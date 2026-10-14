import argparse, collections, datetime as dt, html, json, math, random, re, statistics, sys

# ----------------------------------------------------------------- field mapping
ALIASES = {
    "ts":      ["ts", "time", "timestamp", "@timestamp", "t", "datetime", "date"],
    "level":   ["level", "severity", "lvl", "levelname", "loglevel"],
    "msg":     ["message", "msg", "event", "text"],
    "service": ["service", "logger", "app", "component", "name", "module"],
    "lat":     ["latency_ms", "duration_ms", "elapsed_ms", "took_ms", "latency", "duration", "elapsed"],
}
LEVELS = {"TRACE": 0, "DEBUG": 1, "INFO": 2, "NOTICE": 2, "WARN": 3, "WARNING": 3,
          "ERROR": 4, "ERR": 4, "CRITICAL": 5, "FATAL": 5, "EMERG": 5}
CANON = {0: "TRACE", 1: "DEBUG", 2: "INFO", 3: "WARN", 4: "ERROR", 5: "FATAL"}


def dig(rec, key):
    """Lookup with dotted-path support, case-insensitive on the top level."""
    if key in rec:
        return rec[key]
    low = {k.lower(): k for k in rec if isinstance(k, str)}
    if key.lower() in low:
        return rec[low[key.lower()]]
    cur = rec
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def pick(rec, field):
    for k in ALIASES[field]:
        v = dig(rec, k)
        if v is not None:
            return v
    return None


def parse_ts(v):
    if v is None:
        return None
    try:
        if isinstance(v, (int, float)):
            return v / 1000.0 if v > 1e11 else float(v)
        s = str(v).strip()
        if re.fullmatch(r"\d+(\.\d+)?", s):
            return parse_ts(float(s))
        s = s.replace("Z", "+00:00")
        d = dt.datetime.fromisoformat(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d.timestamp()
    except (ValueError, OverflowError):
        return None


def parse_level(v):
    if v is None:
        return "INFO"
    if isinstance(v, (int, float)):  # syslog-ish / pino numeric levels
        n = int(v)
        return CANON[min(5, max(0, n // 10 - 1 if n >= 10 else n))]
    return CANON[LEVELS.get(str(v).strip().upper(), 2)]


def parse_lat(v):
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None

MASKS = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-f]{16,}\b"), "<HEX>"),
    (re.compile(r"(?<![\w<])/[\w\-.]+(?:/[\w\-.]+)*"), "<PATH>"),
    (re.compile(r"\"[^\"]*\"|'[^']*'"), "<STR>"),
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|kb|mb|gb|%)?\b", re.I), "<N>"),
]


def template(msg):
    s = str(msg)
    for rx, tok in MASKS:
        s = rx.sub(tok, s)
    return re.sub(r"\s+", " ", s).strip()[:160]

def read_records(fp):
    """Yield (record|None, raw_line_no). Auto-detect JSON array vs NDJSON."""
    first = fp.read(1)
    while first and first.isspace():
        first = fp.read(1)
    if not first:
        return
    if first == "[":
        try:
            data = json.loads("[" + fp.read())
        except json.JSONDecodeError as e:
            sys.exit(f"error: invalid JSON array ({e})")
        for i, r in enumerate(data, 1):
            yield (r if isinstance(r, dict) else None), i
        return
    buf = first + fp.readline()
    n = 1
    while buf:
        line = buf.strip()
        if line:
            try:
                r = json.loads(line)
                yield (r if isinstance(r, dict) else None), n
            except json.JSONDecodeError:
                yield None, n
        buf = fp.readline()
        n += 1

def pctl(sorted_vals, p):
    if not sorted_vals:
        return None
    k = (len(sorted_vals) - 1) * p / 100
    f, c = math.floor(k), math.ceil(k)
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)

def analyze(fp, min_level="DEBUG", top=10):
    floor = LEVELS[min_level.upper()]
    rows, bad, total = [], 0, 0
    for rec, _ in read_records(fp):
        total += 1
        if rec is None:
            bad += 1
            continue
        lvl = parse_level(pick(rec, "level"))
        if LEVELS[lvl] < floor:
            continue
        msg = pick(rec, "msg")
        if msg is None:
            msg = json.dumps({k: v for k, v in rec.items()
                              if k.lower() not in sum(ALIASES.values(), [])}, default=str)[:160]
        svc = pick(rec, "service")
        rows.append((parse_ts(pick(rec, "ts")), lvl, str(msg),
                     str(svc) if svc is not None else "-", parse_lat(pick(rec, "lat"))))
    if not rows:
        sys.exit("no usable log records found")

    stamped = [r for r in rows if r[0] is not None]
    t0 = min(r[0] for r in stamped) if stamped else None
    t1 = max(r[0] for r in stamped) if stamped else None

    levels = collections.Counter(r[1] for r in rows)
    services = collections.defaultdict(collections.Counter)
    tmpl = collections.Counter()
    tmpl_lvl = {}
    tmpl_first = {}
    tmpl_example = {}
    lat_all, lat_svc = [], collections.defaultdict(list)

    for ts, lvl, msg, svc, lat in rows:
        services[svc][lvl] += 1
        t = template(msg)
        tmpl[t] += 1
        if t not in tmpl_lvl or LEVELS[lvl] > LEVELS[tmpl_lvl[t]]:
            tmpl_lvl[t] = lvl
        tmpl_example.setdefault(t, msg[:160])
        if ts is not None and t not in tmpl_first:
            tmpl_first[t] = ts
        if lat is not None:
            lat_all.append(lat)
            lat_svc[svc].append(lat)

    buckets, anomalies, bsize = [], [], None
    if stamped and t1 > t0:
        span = t1 - t0
        for cand in (1, 5, 10, 30, 60, 300, 600, 1800, 3600, 21600, 86400):
            if span / cand <= 60:
                bsize = cand
                break
        bsize = bsize or 86400
        n = int(span // bsize) + 1
        tot, err = [0] * n, [0] * n
        for ts, lvl, *_ in stamped:
            i = int((ts - t0) // bsize)
            tot[i] += 1
            if LEVELS[lvl] >= 4:
                err[i] += 1
        buckets = list(zip(tot, err))
        med = statistics.median(err)
        mad = statistics.median([abs(e - med) for e in err]) or 0.5
        for i, e in enumerate(err):
            z = 0.6745 * (e - med) / mad  
            if z > 3.5 and e > 0:
                anomalies.append((t0 + i * bsize, e, round(z, 1)))

    late = []
    if stamped and t1 > t0:
        cut = t1 - (t1 - t0) * 0.10
        late = [(t, tmpl[t], tmpl_lvl[t]) for t, f in tmpl_first.items()
                if f >= cut and LEVELS[tmpl_lvl[t]] >= 3]
        late.sort(key=lambda x: -x[1])

    def lat_stats(v):
        v = sorted(v)
        return {"n": len(v), "p50": pctl(v, 50), "p95": pctl(v, 95), "p99": pctl(v, 99), "max": v[-1]}

    errs = sorted(((c, t) for t, c in tmpl.items() if LEVELS[tmpl_lvl[t]] >= 4), reverse=True)

    return {
        "total_lines": total, "bad_lines": bad, "records": len(rows),
        "start": t0, "end": t1, "bucket_seconds": bsize, "buckets": buckets,
        "levels": dict(levels),
        "services": {s: dict(c) for s, c in services.items()},
        "top_templates": [(t, c, tmpl_lvl[t], tmpl_example[t]) for t, c in tmpl.most_common(top)],
        "top_errors": [(t, c) for c, t in errs[:top]],
        "anomalies": [{"time": a, "errors": e, "z": z} for a, e, z in anomalies],
        "late_templates": late[:top],
        "latency": lat_stats(lat_all) if lat_all else None,
        "latency_by_service": {s: lat_stats(v) for s, v in lat_svc.items()},
        "error_rate": (sum(c for l, c in levels.items() if LEVELS[l] >= 4) / len(rows)),
    }

def fmt_t(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "n/a"


def spark(vals):
    bars = "▁▂▃▄▅▆▇█"
    m = max(vals) or 1
    return "".join(bars[min(7, int(v / m * 7.999))] for v in vals)


def text_report(r):
    o = []
    o.append("=" * 72)
    o.append(" LOGSCOPE REPORT")
    o.append("=" * 72)
    o.append(f" Lines: {r['total_lines']}  parsed: {r['records']}  malformed: {r['bad_lines']}")
    o.append(f" Window: {fmt_t(r['start'])} -> {fmt_t(r['end'])} UTC")
    o.append(f" Error rate (ERROR+FATAL): {r['error_rate']*100:.2f}%")
    o.append("\n LEVELS")
    for l in ["FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"]:
        if l in r["levels"]:
            c = r["levels"][l]
            o.append(f"  {l:<6}{c:>8}  {'#' * max(1, int(40 * c / r['records']))}")
    if r["buckets"]:
        o.append(f"\n ERRORS OVER TIME (bucket={r['bucket_seconds']}s)")
        o.append("  " + spark([e for _, e in r["buckets"]]))
        o.append(" VOLUME")
        o.append("  " + spark([t for t, _ in r["buckets"]]))
    if r["anomalies"]:
        o.append("\n ANOMALOUS ERROR BURSTS (modified z > 3.5)")
        for a in r["anomalies"]:
            o.append(f"  {fmt_t(a['time'])}  errors={a['errors']}  z={a['z']}")
    o.append("\n SERVICES")
    for s, c in sorted(r["services"].items(), key=lambda x: -sum(x[1].values())):
        e = sum(v for l, v in c.items() if LEVELS[l] >= 4)
        o.append(f"  {s:<22}{sum(c.values()):>8} logs  {e:>6} errors")
    if r["latency"]:
        o.append("\n LATENCY (ms)        n      p50      p95      p99      max")
        o.append(f"  {'ALL':<14}" + _lat_row(r["latency"]))
        for s, v in sorted(r["latency_by_service"].items(), key=lambda x: -(x[1]["p95"] or 0)):
            o.append(f"  {s[:14]:<14}" + _lat_row(v))
    o.append("\n TOP MESSAGE PATTERNS")
    for t, c, l, _ in r["top_templates"]:
        o.append(f"  {c:>7}  [{l:<5}] {t}")
    if r["top_errors"]:
        o.append("\n TOP ERROR PATTERNS")
        for t, c in r["top_errors"]:
            o.append(f"  {c:>7}  {t}")
    if r["late_templates"]:
        o.append("\n NEW WARN/ERROR PATTERNS IN LAST 10% OF TIMELINE (possible regression)")
        for t, c, l in r["late_templates"]:
            o.append(f"  {c:>7}  [{l:<5}] {t}")
    return "\n".join(o)


def _lat_row(v):
    return f"{v['n']:>6}{v['p50']:>9.1f}{v['p95']:>9.1f}{v['p99']:>9.1f}{v['max']:>9.1f}"


def html_report(r):
    e = html.escape
    w, h = 900, 160
    svg = ""
    if r["buckets"]:
        n = len(r["buckets"])
        mt = max(t for t, _ in r["buckets"]) or 1
        bw = w / n
        for i, (t, er) in enumerate(r["buckets"]):
            th, eh = t / mt * (h - 20), er / mt * (h - 20)
            svg += f'<rect x="{i*bw+1:.1f}" y="{h-th:.1f}" width="{bw-2:.1f}" height="{th:.1f}" fill="#9db4d6"/>'
            svg += f'<rect x="{i*bw+1:.1f}" y="{h-eh:.1f}" width="{bw-2:.1f}" height="{eh:.1f}" fill="#d64545"/>'
        svg = f'<svg viewBox="0 0 {w} {h}" width="100%">{svg}</svg>'
    rows = lambda items: "".join(f"<tr>{''.join(f'<td>{e(str(c))}</td>' for c in it)}</tr>" for it in items)
    lat = ""
    if r["latency"]:
        lat = "<h2>Latency (ms)</h2><table><tr><th>service</th><th>n</th><th>p50</th><th>p95</th><th>p99</th><th>max</th></tr>" + \
              rows([("ALL", v["n"], *(f"{v[k]:.1f}" for k in ("p50", "p95", "p99", "max")))
                    for v in [r["latency"]]] +
                   [(s, v["n"], *(f"{v[k]:.1f}" for k in ("p50", "p95", "p99", "max")))
                    for s, v in r["latency_by_service"].items()]) + "</table>"
    return f"""<!doctype html><meta charset=utf-8><title>LogScope</title>
<style>body{{font:14px system-ui;max-width:960px;margin:2em auto;padding:0 1em;color:#222}}
table{{border-collapse:collapse;width:100%;margin-bottom:1em}}td,th{{border-bottom:1px solid #ddd;padding:4px 8px;text-align:left}}
.k{{display:inline-block;padding:8px 14px;margin:0 8px 8px 0;background:#f2f4f8;border-radius:8px}}
code{{font-size:12px}}</style>
<h1>LogScope report</h1>
<span class=k>records <b>{r['records']}</b></span><span class=k>malformed <b>{r['bad_lines']}</b></span>
<span class=k>error rate <b>{r['error_rate']*100:.2f}%</b></span>
<span class=k>{e(fmt_t(r['start']))} → {e(fmt_t(r['end']))} UTC</span>
<h2>Volume (blue) &amp; errors (red) per {r['bucket_seconds']}s</h2>{svg}
<h2>Anomalous error bursts</h2><table><tr><th>time</th><th>errors</th><th>z</th></tr>{rows((fmt_t(a['time']), a['errors'], a['z']) for a in r['anomalies'])}</table>
<h2>Levels</h2><table>{rows(sorted(r['levels'].items(), key=lambda x: -x[1]))}</table>
{lat}
<h2>Top patterns</h2><table><tr><th>count</th><th>level</th><th>pattern</th></tr>{rows((c, l, t) for t, c, l, _ in r['top_templates'])}</table>
<h2>New late WARN/ERROR patterns</h2><table>{rows((c, l, t) for t, c, l in r['late_templates'])}</table>"""


def make_demo(path, n=6000):
    random.seed(7)
    base = dt.datetime(2026, 10, 1, 9, 0, tzinfo=dt.timezone.utc).timestamp()
    svcs = ["auth", "payments", "gateway", "search"]
    with open(path, "w") as f:
        for i in range(n):
            ts = base + i * 0.6
            s = random.choice(svcs)
            lat = random.lognormvariate(4.2, 0.5) * (3 if s == "payments" else 1)
            lvl, msg = "INFO", f"GET /api/v1/items/{random.randint(1, 9999)} 200 in {int(lat)}ms from 10.0.{random.randint(0,9)}.{random.randint(1,254)}"
            r = random.random()
            if r < 0.04:
                lvl, msg = "WARN", f"slow query took {random.randint(800, 3000)}ms on table orders"
            if r < 0.015:
                lvl, msg = "ERROR", f"timeout calling upstream host 10.1.0.{random.randint(1,50)}"
            if 2400 < i < 2600 and random.random() < 0.35:   # injected incident
                lvl, msg = "ERROR", f"db connection pool exhausted (active={random.randint(95,100)})"
            if i > n * 0.93 and random.random() < 0.05:     # late regression
                lvl, msg = "ERROR", f"payment {random.randint(1000,9999)} rejected: invalid signature"
            rec = {"timestamp": dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(),
                   "level": lvl, "service": s, "message": msg, "latency_ms": round(lat, 1)}
            if i % 997 == 0:
                f.write("{corrupt line\n")
            f.write(json.dumps(rec) + "\n")

def main():
    ap = argparse.ArgumentParser(description="JSON log file analyzer")
    ap.add_argument("file", nargs="?", help="log file path or - for stdin")
    ap.add_argument("--demo", action="store_true", help="generate demo.jsonl and analyze it")
    ap.add_argument("--min-level", default="DEBUG", choices=[k for k in LEVELS])
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--html", help="write HTML report to this path")
    ap.add_argument("--json", help="write JSON summary to this path")
    a = ap.parse_args()

    if not a.file and not a.demo:            
        print("No file given, running the built-in demo.")
        print("Tip: python logscope.py yourlogs.jsonl [--html report.html]\n")
        a.demo = True
    if a.demo:
        make_demo("demo.jsonl")
        print("generated demo.jsonl\n")
        a.file = "demo.jsonl"
        a.html = a.html or "demo_report.html"

    fp = sys.stdin if a.file == "-" else open(a.file, encoding="utf-8", errors="replace")
    with fp:
        r = analyze(fp, a.min_level, a.top)
    print(text_report(r))
    if a.html:
        open(a.html, "w", encoding="utf-8").write(html_report(r))
        print(f"\nHTML report -> {a.html}")
    if a.json:
        json.dump(r, open(a.json, "w"), indent=2, default=str)
        print(f"JSON summary -> {a.json}")


if __name__ == "__main__":
    main()