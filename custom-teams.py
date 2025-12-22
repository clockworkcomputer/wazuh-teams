#!/usr/bin/env python3
import sys
import json
import logging
import requests
from datetime import datetime

LOG_FILE = "/var/ossec/logs/integrations.log"
USER_AGENT = "Wazuh-Teams-Integration/3.1"

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
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger("wazuh-teams")

    def _validate(self):
        if not self.alert_file or not self.alert_file.endswith(".alert"):
            self.logger.error(f"Invalid alert file: {self.alert_file}")
            return False

        if not self.webhook_url:
            self.logger.error("Webhook URL not provided")
            return False

        allowed_hosts = (
            "environment.api.powerplatform.com",  # Power Automate workflows
            "logic.azure.com",                    # Logic Apps style
        )
        if not any(h in self.webhook_url for h in allowed_hosts):
            self.logger.error(f"Invalid webhook URL: {self.webhook_url}")
            return False

        return True

    def _load_alert(self):
        try:
            with open(self.alert_file, "r") as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Cannot load alert JSON: {e}")
            return {}

    def _format_time(self, ts: str) -> str:
        if not ts:
            return "N/A"
        try:
            # Wazuh often uses +0000; convert to +00:00 for fromisoformat
            if len(ts) > 5 and (ts[-5] in ["+", "-"]) and ts[-2:].isdigit():
                ts_fixed = ts[:-2] + ":" + ts[-2:]
            else:
                ts_fixed = ts
            dt = datetime.fromisoformat(ts_fixed)
            return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts

    def _priority(self, lvl: int):
        if lvl >= 12: return ("CRITICAL", "Attention")
        if lvl >= 7:  return ("HIGH", "Warning")
        if lvl >= 4:  return ("MEDIUM", "Good")
        return ("LOW", "Accent")

    def _make_payload(self, alert: dict) -> dict:
        rule = alert.get("rule", {}) or {}
        agent = alert.get("agent", {}) or {}

        lvl = int(rule.get("level", 0))
        pr_txt, pr_clr = self._priority(lvl)

        desc = rule.get("description", "N/A")
        rid  = str(rule.get("id", "N/A"))
        agent_name = agent.get("name", "manager")
        agent_ip   = agent.get("ip", "N/A")
        ts = self._format_time(alert.get("timestamp", ""))
        full_log = (alert.get("full_log") or "(N/A)").strip()
        if len(full_log) > 900:
            full_log = full_log[:900] + "…"

        adaptive_card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "TextBlock",
                    "text": f"{pr_txt} WAZUH ALERT",
                    "weight": "Bolder",
                    "size": "Large",
                    "color": pr_clr,
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Level", "value": f"{pr_txt} ({lvl})"},
                        {"title": "Rule ID", "value": rid},
                        {"title": "Description", "value": desc},
                        {"title": "Agent", "value": f"{agent_name} ({agent_ip})"},
                        {"title": "Timestamp", "value": ts},
                    ],
                },
                {
                    "type": "TextBlock",
                    "text": full_log,
                    "wrap": True,
                    "spacing": "Small",
                    "isSubtle": True,
                    "fontType": "Monospace",
                },
            ],
        }

        # IMPORTANT: Flow expects "type":"message" + attachments with AdaptiveCard content
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": adaptive_card,
                }
            ],
        }

    def _send(self, payload: dict) -> bool:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        try:
            resp = requests.post(self.webhook_url, json=payload, headers=headers, timeout=30)
            if resp.status_code in (200, 202):
                self.logger.info(f"custom-teams: Sent ok (status {resp.status_code})")
                return True
            self.logger.error(f"custom-teams: Send failed: {resp.status_code} {resp.text}")
            return False
        except Exception as e:
            self.logger.error(f"custom-teams: Exception: {e}")
            return False

    def run(self):
        if not self._validate():
            sys.exit(1)

        alert = self._load_alert()
        if not alert:
            sys.exit(1)

        alert_level = int((alert.get("rule", {}) or {}).get("level", 0))
        if alert_level < self.min_level:
            self.logger.info(f"custom-teams: Skipped (alert level {alert_level} < configured {self.min_level})")
            sys.exit(0)

        payload = self._make_payload(alert)
        ok = self._send(payload)
        sys.exit(0 if ok else 1)

def parse_args(argv):
    alert_file = None
    webhook = None
    level = None

    for arg in argv[1:]:
        if arg.startswith("/tmp/") and arg.endswith(".alert"):
            alert_file = arg
        elif arg.startswith("http://") or arg.startswith("https://"):
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
        print("Usage: custom-teams.py <alert_file.alert> <webhook_url> [min_level]")
        sys.exit(1)

    Integration(af, wh, lv).run()

if __name__ == "__main__":
    main()
