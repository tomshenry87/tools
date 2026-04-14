import urllib.request, base64, re

host = "berry-180-pdu-1.openav.dartmouth.edu"
creds = base64.b64encode(b"admin:NiLE2j7rQzDoSg").decode()
hdrs = {"Authorization": "Basic " + creds, "Accept-Encoding": "identity"}

# Get full app.js
req = urllib.request.Request(f"http://{host}/assets/js/app.js", headers=hdrs)
resp = urllib.request.urlopen(req, timeout=10)
js = resp.read().decode("utf-8", errors="replace")

# Search for POST, PUT, ajax with type/method, and any write-like patterns
for i, line in enumerate(js.split("\n")):
    low = line.lower()
    if any(k in low for k in ["type: ", "type:", "method:",
                               "post", "put", "save", "submit",
                               "$.ajax", "cgi", ".php",
                               "writesettings", "applysettings",
                               "setsettings", "update",
                               "reboot", "restart", "cycle",
                               "outlet_control", "outletcontrol",
                               "setoutlet", "set_outlet"]):
        print(f"L{i}: {line.strip()[:250]}")
