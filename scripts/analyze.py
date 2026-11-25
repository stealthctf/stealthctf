import os, re, sys, json, glob, tarfile
from collections import defaultdict

d = sys.argv[1] if len(sys.argv) > 1 else "logs"
# Only alerts from the event day are counted. One archive also holds a few
# entries from tests on 11-13 Sep 2024, which are skipped and reported below.
EVENT_DAY = "2024-09-18"
# A team "loaded an OFBiz application page" if the Apache access log has a
# 200 response for a control-servlet URL on the event day. Times are UTC
# (the paper uses local time, CEST = UTC+2).
APP_PAGE = re.compile(r'\[18/Sep/2024:(\d\d:\d\d:\d\d) [^\]]*\] "(?:GET|POST) /[a-z]+/control/\S* HTTP/[0-9.]+" 200 ')
teams = sorted(x for x in os.listdir(d) if os.path.isdir(os.path.join(d, x)))

seen = set()
n = defaultdict(int)
ex = defaultdict(int)
found = defaultdict(bool)
first_app = {}
skipped = 0
cat = defaultdict(int)
raw = 0

for t in teams:
    files = sorted(glob.glob(os.path.join(d, t, "*.tar.gz")))
    for f in files:
        try:
            tf = tarfile.open(f, "r:xz")
        except Exception:
            continue
        target = None
        for mem in tf.getmembers():
            if mem.name.endswith("alerts/alerts.json"):
                target = mem
            elif mem.isfile() and mem.name.endswith("apache2/access.log"):
                for row in tf.extractfile(mem).read().decode("utf-8", "replace").splitlines():
                    m = APP_PAGE.search(row)
                    if m:
                        if t not in first_app or m.group(1) < first_app[t]:
                            first_app[t] = m.group(1)
                        break
        if not target:
            tf.close()
            continue
        blob = tf.extractfile(target).read().decode("utf-8", "replace")
        tf.close()
        for line in blob.splitlines():
            line = line.strip()
            if not line:
                continue
            raw += 1
            try:
                a = json.loads(line)
            except Exception:
                continue
            key = (t, a.get("timestamp"), a.get("full_log", ""))
            if key in seen:
                continue
            seen.add(key)
            if not str(a.get("timestamp", "")).startswith(EVENT_DAY):
                skipped += 1
                continue
            n[t] += 1
            r = a.get("rule", {})
            cat[r.get("description", "")] += 1
            if r.get("id") == "100002":
                ex[t] += 1
            if "programexport" in a.get("full_log", "").lower():
                found[t] = True

tot = sum(n.values())
print("raw lines:", raw)
print("unique alerts outside the event day (skipped):", skipped)
print("unique alerts:", tot)
print("duplicate share: {}%".format(round(100 * (raw - tot - skipped) / raw)))
print("exploit rule 100002:", sum(ex.values()))
print()
print("team".ljust(10), "alerts", "exploit", "app", "endpoint", "first_app_page_utc")
for t in teams:
    print(t.ljust(10), str(n[t]).rjust(6), str(ex[t]).rjust(7), " " + ("yes" if t in first_app else "no").ljust(3), " " + ("yes" if found[t] else "no").ljust(8), first_app.get(t, "-"))
print()
print("loaded an OFBiz application page:", len(first_app), "of", len(teams))
print("reached endpoint:", sum(1 for t in teams if found[t]), "of", len(teams))
print()
for k, v in sorted(cat.items(), key=lambda kv: -kv[1])[:6]:
    print(str(v).rjust(7), k)
