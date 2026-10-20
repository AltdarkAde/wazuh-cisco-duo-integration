#!/opt/duo-venv/bin/python
import duo_client, json, time, os

def load_env(path):
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k] = v

load_env("/var/ossec/integrations/duo.env")

STATE = "/var/ossec/integrations/.duo_last"
OUT = "/var/log/duo/duo.log"

admin = duo_client.Admin(ikey=os.environ["DUO_IKEY"],
                         skey=os.environ["DUO_SKEY"],
                         host=os.environ["DUO_HOST"])

now = int(time.time())
maxtime = (now - 120) * 1000                      # Duo needs logs >2 min old
last = int(open(STATE).read()) if os.path.exists(STATE) else (now - 900) * 1000

with open(OUT, "a") as f:
    offset = None
    while True:
        r = admin.get_authentication_log(api_version=2, mintime=last,
                                         maxtime=maxtime, next_offset=offset,
                                         limit="1000")
        for e in r["authlogs"]:
            e["duo_log_type"] = "authentication"
            f.write(json.dumps(e) + "\n")
        offset = r["metadata"].get("next_offset")
        if not offset:
            break

    for e in admin.get_administrator_log(mintime=last // 1000):
        e["duo_log_type"] = "administrator"
        f.write(json.dumps(e) + "\n")

open(STATE, "w").write(str(maxtime + 1))
