import urllib.request, base64, re

host = "berry-180-pdu-1.openav.dartmouth.edu"
creds = base64.b64encode(b"admin:NiLE2j7rQzDoSg").decode()
hdrs = {"Authorization": "Basic " + creds, "Accept-Encoding": "identity"}

all_js = ""
for jspath in ["/assets/js/app.js", "/assets/js/main.js"]:
    try:
        req = urllib.request.Request(f"http://{host}{jspath}", headers=hdrs)
        resp = urllib.request.urlopen(req, timeout=10)
        all_js += resp.read().decode("utf-8", errors="replace")
    except:
        pass

urls = set()
for m in re.finditer(r'["\']([^"\']*\.json)["\']', all_js):
    urls.add(m.group(1))
for m in re.finditer(r'url\s*[:=]\s*["\']([^"\']+)["\']', all_js):
    urls.add(m.group(1))

print("=== ENDPOINTS FOUND IN JS ===")
for u in sorted(urls):
    print(f"  {u}")

print()
print("=== PROBING ENDPOINTS ===")

guesses = {
    "assets/js/json/settings.json",
    "assets/js/json/log.json",
    "assets/js/json/network.json",
    "assets/js/json/outlets.json",
    "assets/js/json/device.json",
    "assets/js/json/firmware.json",
    "assets/js/json/status.json",
    "assets/js/json/system.json",
    "assets/js/json/autoping.json",
    "assets/js/json/email.json",
    "assets/js/json/sequence.json",
    "assets/js/json/cloud.json",
    "assets/js/json/datetime.json",
}
to_probe = urls | guesses

seen = set()
for path in sorted(to_probe):
    p = path.lstrip("/")
    if p in seen:
        continue
    seen.add(p)
    try:
        req = urllib.request.Request(f"http://{host}/{p}", headers=hdrs)
        resp = urllib.request.urlopen(req, timeout=5)
        body = resp.read().decode("utf-8", errors="replace")
        print(f"  200 /{p} ({len(body)} bytes)")
        print(f"      {body[:300]}")
        print()
    except Exception as e:
        code = getattr(e, "code", "?")
        print(f"  {code} /{p}")
