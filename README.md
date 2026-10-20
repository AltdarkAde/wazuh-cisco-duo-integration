# Cisco Duo + Wazuh Integration

Collect Cisco Duo authentication and administrator logs with the Duo Admin API and ingest them into Wazuh as JSON, with custom rules for failed MFA, repeated failures and admin changes.

Duo has no native Wazuh connector, so a small Python collector polls the Admin API every 5 minutes and appends events to a log file that the Wazuh logcollector reads.

```mermaid
flowchart LR
    A["Duo Admin API"] -->|"HTTPS poll, every 5 min"| B["duo_pull.py (cron)"]
    B -->|"JSON lines"| C["/var/log/duo/duo.log"]
    C --> D["Wazuh logcollector"]
    D --> E["Rules 100500-100503"]
    E --> F["alerts.json"]
    F --> G["Wazuh dashboard"]
```

**Tested on:** Ubuntu 24.04, Wazuh 4.14.0 (single node), Python 3.12, `duo_client` 5.7.0.

## Repository layout

```
.
├── README.md                    # this guide
├── LICENSE
├── scripts/
│   └── duo_pull.py              # Duo Admin API collector
├── rules/
│   └── duo_rules.xml            # Wazuh rules 100500-100503
└── config/
    ├── duo.env.example          # credentials template (copy, fill, chmod 600)
    ├── duo-wazuh.cron           # /etc/cron.d/duo-wazuh
    ├── duo.logrotate            # /etc/logrotate.d/duo
    └── ossec-localfile.xml      # <localfile> block for ossec.conf
```

Each step below shows the commands inline, and the same files are in the repo for copying.

---

## Prerequisites

- Wazuh manager with root access
- Duo admin with the **Owner** role (needed to create an Admin API application)
- Outbound HTTPS from the Wazuh manager to `api-xxxxxxxx.duosecurity.com`
- The manager's **public (egress) IP**, if you want to restrict API access

---

## Step 1: Create the Admin API application in Duo

1. In the Duo Admin Panel go to **Applications > Add application**.
2. Search for **Admin API** and click **Protect**.
3. Under **Permissions**, tick **Grant read log** only. Leave everything else off.
4. Under **Networks for API access**, enter the manager's public IP (`curl -s https://ifconfig.me` on the manager). Duo only accepts public IPs here, and it sees the address after NAT. Leaving it blank allows the API from any network, so restricting it is better practice.
5. Copy the **Integration key**, **Secret key** and **API hostname**.

> Never commit these values to Git.

---

## Step 2: Install the Duo client in a virtual environment

Ubuntu 24.04 enforces PEP 668, so `pip install` system-wide fails with `externally-managed-environment`. Use a dedicated venv:

```bash
apt update && apt install -y python3-venv python3-full
python3 -m venv /opt/duo-venv
/opt/duo-venv/bin/pip install duo_client
mkdir -p /var/log/duo /var/ossec/integrations

/opt/duo-venv/bin/python -c "import duo_client; print('ok')"
```

---

## Step 3: Store the credentials

Keep the secrets in a root-only file, not in the script:

```bash
cat > /var/ossec/integrations/duo.env << 'EOF'
DUO_IKEY=YOUR_INTEGRATION_KEY
DUO_SKEY=YOUR_SECRET_KEY
DUO_HOST=api-xxxxxxxx.duosecurity.com
EOF
chmod 600 /var/ossec/integrations/duo.env
```

---

## Step 4: Create the collector script

`/var/ossec/integrations/duo_pull.py`:

```python
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
```

```bash
chmod 700 /var/ossec/integrations/duo_pull.py
```

The script adds a `duo_log_type` field (`authentication` or `administrator`) that the Wazuh rules key on.

Test it manually:

```bash
/opt/duo-venv/bin/python /var/ossec/integrations/duo_pull.py
tail -n 3 /var/log/duo/duo.log
```

An empty log is normal if nobody authenticated in the last 15 minutes. A traceback with `Access denied` or `Invalid IP` means the **Networks for API access** value does not match the IP Duo sees.

---

## Step 5: Schedule it with cron

```bash
echo "*/5 * * * * root /opt/duo-venv/bin/python /var/ossec/integrations/duo_pull.py >> /var/log/duo/collector_errors.log 2>&1" > /etc/cron.d/duo-wazuh
chmod 644 /etc/cron.d/duo-wazuh
```

Confirm cron fired:

```bash
grep duo_pull /var/log/syslog | tail -n 3
```

---

## Step 6: Tell Wazuh to read the log

Add inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/duo/duo.log</location>
</localfile>
```

---

## Step 7: Add the custom rules

Install `rules/duo_rules.xml` as `/var/ossec/etc/rules/duo_rules.xml`, or paste the block into `local_rules.xml`. Do one or the other, not both, because duplicate IDs stop the manager loading them. Rule IDs must be unique, so check for conflicts first:

```bash
grep -rhoE 'rule id="1005[0-9]{2}"' /var/ossec/etc/rules/
```

```xml
<group name="duo,">

  <!-- Every Duo authentication event.
       Child of 86600 - see "Gotchas" below for why. -->
  <rule id="100500" level="3">
    <if_sid>86600</if_sid>
    <field name="duo_log_type">authentication</field>
    <description>Duo: authentication $(result) for $(user.name)</description>
  </rule>

  <!-- Failed / denied / fraud / error results -->
  <rule id="100501" level="7">
    <if_sid>100500</if_sid>
    <field name="result" type="pcre2">(?i)^(denied|failure|fraud|error)$</field>
    <description>Duo: authentication $(result) for $(user.name)</description>
  </rule>

  <!-- 5 failures for the same user within 5 minutes -->
  <rule id="100502" level="10" frequency="5" timeframe="300">
    <if_matched_sid>100501</if_matched_sid>
    <same_field>user.name</same_field>
    <description>Duo: multiple failed authentications for $(user.name)</description>
  </rule>

  <!-- Duo administrator actions -->
  <rule id="100503" level="8">
    <decoded_as>json</decoded_as>
    <field name="duo_log_type">administrator</field>
    <description>Duo: administrator action $(action)</description>
  </rule>

</group>
```

| Rule | Level | Purpose |
|---|---|---|
| 100500 | 3 | Any Duo authentication event |
| 100501 | 7 | Result is denied, failure, fraud or error |
| 100502 | 10 | 5 failures for one user in 5 minutes |
| 100503 | 8 | Administrator action in Duo |

---

## Step 8: Validate, test and restart

Check the config parses:

```bash
/var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; echo "config test: $?"    # expect 0
```

Test with a **real line from your log**, not a trimmed sample (see Gotchas):

```bash
tail -n 1 /var/log/duo/duo.log | /var/ossec/bin/wazuh-logtest 2>&1 | grep -E "^\s+id:|level:|description:"
```

Expected: `id: '100500'`, `level: '3'`, `Duo: authentication success for <user>`.

Restart:

```bash
systemctl restart wazuh-manager
/var/ossec/bin/wazuh-control status
```

---

## Step 9: Verify end to end

Inject a test event and confirm it alerts (use a fake user name):

```bash
echo '{"event_type": "authentication", "timestamp": 1792500000, "factor": "duo_push", "reason": "user_approved", "result": "success", "user": {"name": "wazuh.test"}, "application": {"name": "Microsoft RDP"}, "eventtype": "authentication", "duo_log_type": "authentication"}' >> /var/log/duo/duo.log
sleep 15
grep -c 'Duo: authentication success for wazuh.test' /var/ossec/logs/alerts/alerts.json
```

Then in the Wazuh dashboard, open **Threat Hunting** and search `rule.groups: duo`.

Useful checks:

```bash
# alerts by result and user
grep '"duo"' /var/ossec/logs/alerts/alerts.json | grep -o 'Duo: authentication [a-z]* for [^"]*' | sort | uniq -c

# failed-auth alerts as a table (no phone numbers or emails)
grep '"id":"100501"' /var/ossec/logs/alerts/alerts.json | jq -r '[.timestamp, .data.user.name, .data.reason, .data.application.name] | @tsv'
```

To test the escalation rule, paste this into `wazuh-logtest` five times quickly. The fifth should trigger 100502:

```
{"event_type": "authentication", "timestamp": 1792493526, "factor": "duo_push", "reason": "user_marked_fraud", "result": "fraud", "user": {"name": "test.user"}, "application": {"name": "Microsoft RDP"}, "duo_log_type": "authentication"}
```

---

## Step 10: Log rotation

`/etc/logrotate.d/duo`:

```
/var/log/duo/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate` lets Wazuh keep reading the file without a restart. Check with `logrotate -d /etc/logrotate.d/duo`.

Duo logs contain user emails and phone numbers, so restrict access:

```bash
chmod 750 /var/log/duo
chmod 640 /var/log/duo/*.log
```

---

## Gotchas and lessons learned

### 1. Real Duo events were swallowed by the Suricata rule (86600)

Wazuh's stock rule **86600** matches any JSON event with both `event_type` and `timestamp`. Real Duo authentication events have both, so they were classified as level-0 "Suricata messages" and never reached my rule. A trimmed test sample without `timestamp` passed `wazuh-logtest`, which hid the problem.

**Fix:** make rule 100500 a child of 86600 with `<if_sid>86600</if_sid>`. Administrator events have no `event_type`, so rule 100503 does not need this.

**Lesson:** always test rules with an unmodified line from the real log, and check Phase 3 of `wazuh-logtest` to see which rule fired.

### 2. Field values are lowercase

Duo returns `"result": "success"`, `"denied"`, `"fraud"` and so on. Wazuh field matching is case-sensitive, so an uppercase `FAILURE` never matches. Rule 100501 uses a case-insensitive pcre2 pattern.

### 3. Logcollector starts at the end of the file

When logcollector begins monitoring a file, it skips existing content. Events written before a restart may never be read. When testing, use events that arrive **after** the last restart, or inject a test line.

### 4. Quiet does not mean working

`0` alerts right after a restart usually means no new logins, not a broken pipeline. Check the chain in order:

1. `wc -l /var/log/duo/duo.log` and the newest `isotimestamp` (collector)
2. `grep duo /var/ossec/logs/ossec.log` for `Analyzing file: '/var/log/duo/duo.log'` (logcollector)
3. `/var/ossec/var/run/wazuh-logcollector.state` for `events` and `drops` on `duo.log`
4. `wazuh-logtest` on the real line (rules)
5. `alerts.json` (alert output), then the dashboard

### 5. Alert volume

Rule 100500 alerts on every successful login at level 3. To keep only failures, lower 100500 to `level="0"`. It still works as the parent of 100501 and 100502.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `externally-managed-environment` on pip install | Use the venv in Step 2 |
| `Access denied` / `Invalid IP` from the script | **Networks for API access** does not match the manager's public egress IP |
| Cron never runs | File in `/etc/cron.d/` must be owned by root and not world-writable |
| `duo.log` not growing | No authentications yet, or the collector is failing. Check `collector_errors.log` |
| No alerts, event matches rule 86600 | See Gotcha 1 |
| Manager fails to start | Duplicate rule IDs or an XML typo. Run `wazuh-analysisd -t` |
| In `alerts.json` but not the dashboard | Check Filebeat: `filebeat test output` |

---

## Security notes

- Grant the Admin API application **read log** permission only.
- Keep `duo.env` at `600` and the script at `700`, both owned by root.
- Restrict **Networks for API access** to the manager's public IP.
- Rotate the Admin API secret key on a schedule.
- If your SSH sessions are recorded or forwarded to a SIEM, do not `cat` the env file, because the secret would end up in the logs.
- Redact emails, phone numbers, IPs and tenant IDs before sharing logs or screenshots.

---

## Possible next steps

- Notifications (email or Slack) for rules 100501, 100502 and 100503
- Dashboards for MFA failures by user and application
- Alerts on `fraud` results and on repeated `locked_out` or `deny_unenrolled_user` reasons
- Duo Unix (`pam_duo`) on Linux hosts, which Wazuh agents already cover via `auth.log` or `secure`
