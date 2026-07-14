import os, sys, json, glob, tarfile
from collections import defaultdict

d = sys.argv[1] if len(sys.argv) > 1 else "logs"
teams = sorted(x for x in os.listdir(d) if os.path.isdir(os.path.join(d, x)))

seen = set()
n = defaultdict(int)
ex = defaultdict(int)
found = defaultdict(bool)
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
            n[t] += 1
            r = a.get("rule", {})
            cat[r.get("description", "")] += 1
            if r.get("id") == "100002":
                ex[t] += 1
            if "programexport" in a.get("full_log", "").lower():
                found[t] = True

tot = sum(n.values())
print("raw lines:", raw)
print("unique alerts:", tot)
print("duplicate share: {}%".format(round(100 * (raw - tot) / raw)))
print("exploit rule 100002:", sum(ex.values()))
print()
print("team".ljust(10), "alerts", "exploit", "found_ofbiz")
for t in teams:
    print(t.ljust(10), str(n[t]).rjust(6), str(ex[t]).rjust(7), "  " + ("yes" if found[t] else "no"))
print()
print("reached endpoint:", sum(1 for t in teams if found[t]), "of", len(teams))
print()
for k, v in sorted(cat.items(), key=lambda kv: -kv[1])[:6]:
    print(str(v).rjust(7), k)
