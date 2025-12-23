#!/usr/bin/env python3
import sys
import json
import logging
import requests
from datetime import datetime

LOG_FILE = "/var/ossec/logs/integrations.log"
USER_AGENT = "Wazuh-Teams-Integration/4.1"

# CHANGE THIS to your Wazuh Dashboard IP or DNS (e.g. https://wazuh.example.com)
DASHBOARD_BASE = "https://192.168.30.2"

INDEX_PATTERN = "wazuh-alerts-*"
TIME_FROM = "now-90d"
TIME_TO = "now"


class Integration:
    def __init__(self, alert_file, webhook_url, min_level):
        self.alert_file = alert_file
        self.webhook_url = webhook_url
        self.min_level = int(min_level) if min_level is not None else 0
        self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
        )
        self.logger = logging.getLogger("custom-teams")

    def _validate(self):
        if not self.alert_file or not self.alert_file.endswith(".alert"):
            return False
        if not self.webhook_url:
            return False
        allowed = ("environment.api.powerplatform.com", "logic.azure.com")
        return any(h in self.webhook_url for h in allowed)

    def _load_alert(self):
        try:
            with open(self.alert_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _format_time(self, ts):
        try:
            if ts and len(ts) > 5 and ts[-5] in ["+", "-"] and ts[-2:].isdigit():
                ts = ts[:-2] + ":" + ts[-2:]
            return datetime.fromisoformat(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts or "N/A"

    def _priority(self, lvl):
        if lvl >= 12:
            return "CRITICAL", "Attention"
        if lvl >= 7:
            return "HIGH", "Warning"
        if lvl >= 4:
            return "MEDIUM", "Good"
        return "LOW", "Accent"

    def _rison_escape(self, value):
        return str(value).replace("'", "''").strip()

    def _build_filter_a(self, alert_id):
        return (
            "(filters:!(("
            "'$state':(store:appState),"
            "meta:("
            "alias:!n,"
            "disabled:!f,"
            f"index:'{INDEX_PATTERN}',"
            "key:id,"
            "negate:!f,"
            f"params:(query:'{alert_id}'),"
            "type:phrase"
            "),"
            f"query:(match_phrase:(id:'{alert_id}'))"
            ")),"
            "query:(language:kuery,query:''))"
        )

    def _build_g(self):
        return f"(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:{TIME_FROM},to:{TIME_TO}))"

    def _build_dashboard_url(self, alert):
        alert_id = self._rison_escape(alert.get("id", ""))
        a_filter = self._build_filter_a(alert_id) if alert_id else "(filters:!(),query:(language:kuery,query:''))"
        return (
            f"{DASHBOARD_BASE}/app/threat-hunting#/overview/?tab=general&tabView=events"
            f"&_a={a_filter}"
            f"&_g={self._build_g()}"
        )

    def _make_payload(self, alert):
        rule = alert.get("rule", {}) or {}
        agent = alert.get("agent", {}) or {}
        data = alert.get("data", {}) or {}

        level = int(rule.get("level", 0))
        pr_txt, pr_color = self._priority(level)

        facts = [
            {"title": "Level", "value": f"{pr_txt} ({level})"},
            {"title": "Rule ID", "value": str(rule.get("id", "N/A"))},
            {"title": "Description", "value": rule.get("description", "N/A")},
            {"title": "Groups", "value": ", ".join(rule.get("groups", []) or []) or "N/A"},
            {"title": "Agent", "value": f"{agent.get('name','manager')} ({agent.get('ip','N/A')})"},
            {"title": "Timestamp", "value": self._format_time(alert.get("timestamp"))},
            {"title": "Alert ID", "value": str(alert.get("id", "N/A"))},
        ]

        vt_link = (data.get("virustotal", {}) or {}).get("permalink")
        if vt_link:
            facts.append({"title": "VirusTotal", "value": vt_link})

        full_log = (alert.get("full_log") or "(N/A)").strip()
        if len(full_log) > 900:
            full_log = full_log[:900] + "…"

        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "TextBlock",
                    "text": f"{pr_txt} WAZUH ALERT",
                    "weight": "Bolder",
                    "size": "Large",
                    "color": pr_color,
                },
                {"type": "FactSet", "facts": facts},
                {"type": "TextBlock", "text": full_log, "wrap": True, "isSubtle": True, "fontType": "Monospace"},
            ],
            "actions": [
                {"type": "Action.OpenUrl", "title": "Dashboard", "url": self._build_dashboard_url(alert)}
            ],
        }

        if vt_link:
            card["actions"].append({"type": "Action.OpenUrl", "title": "VirusTotal", "url": vt_link})

        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}

    def _send(self, payload):
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        try:
            r = requests.post(self.webhook_url, json=payload, headers=headers, timeout=30)
            return r.status_code in (200, 202)
        except Exception:
            return False

    def run(self):
        if not self._validate():
            sys.exit(1)

        alert = self._load_alert()
        if not alert:
            sys.exit(1)

        if int((alert.get("rule", {}) or {}).get("level", 0)) < self.min_level:
            sys.exit(0)

        payload = self._make_payload(alert)
        sys.exit(0 if self._send(payload) else 1)


def parse_args(argv):
    alert_file = None
    webhook = None
    level = None
    for arg in argv[1:]:
        if arg.startswith("/tmp/") and arg.endswith(".alert"):
            alert_file = arg
        elif arg.startswith("http"):
            webhook = arg
        else:
            try:
                level = int(arg)
            except Exception:
                pass
    return alert_file, webhook, level


def main():
    af, wh, lv = parse_args(sys.argv)
    if not af or not wh:
        sys.exit(1)
    Integration(af, wh, lv).run()


if __name__ == "__main__":
    main()
