#!/usr/bin/env python3
import sys
import json
import logging
import requests
from datetime import datetime

LOG_FILE = "/var/ossec/logs/integrations.log"
USER_AGENT = "Wazuh-Teams-Integration/3.8"

DASHBOARD_BASE = "https://192.168.30.2"
INDEX_PATTERN = "wazuh-alerts-*"

# Bloque wrapped (como el que pegaste que te funciona)
WRAPPED_TIME_FROM = "now-24h"
WRAPPED_TIME_TO = "now"

# Bloque final (el que quieres para no perder eventos antiguos)
FINAL_TIME_FROM = "now-90d"
FINAL_TIME_TO = "now"


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
        self.logger = logging.getLogger("wazuh-teams")

    def _validate(self):
        if not self.alert_file or not self.alert_file.endswith(".alert"):
            self.logger.error(f"Invalid alert file: {self.alert_file}")
            return False

        if not self.webhook_url:
            self.logger.error("Webhook URL not provided")
            return False

        allowed_hosts = ("environment.api.powerplatform.com", "logic.azure.com")
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
            if len(ts) > 5 and (ts[-5] in ["+", "-"]) and ts[-2:].isdigit():
                ts_fixed = ts[:-2] + ":" + ts[-2:]
            else:
                ts_fixed = ts
            dt = datetime.fromisoformat(ts_fixed)
            return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts

    def _priority(self, lvl: int):
        if lvl >= 12:
            return ("CRITICAL", "Attention")
        if lvl >= 7:
            return ("HIGH", "Warning")
        if lvl >= 4:
            return ("MEDIUM", "Good")
        return ("LOW", "Accent")

    def _rison_escape(self, s: str) -> str:
        # id va entre comillas simples en Rison -> duplicamos ' si apareciera
        if s is None:
            return ""
        return str(s).replace("'", "''").strip()

    def _build_filter_a(self, wazuh_id: str) -> str:
        # Devuelve el contenido de _a=(...) SIN prefijo "_a=" para poder reutilizarlo
        return (
            "(filters:!(("
            "'$state':(store:appState),"
            "meta:("
            "alias:!n,"
            "disabled:!f,"
            f"index:'{INDEX_PATTERN}',"
            "key:id,"
            "negate:!f,"
            f"params:(query:'{wazuh_id}'),"
            "type:phrase"
            "),"
            f"query:(match_phrase:(id:'{wazuh_id}'))"
            ")),"
            "query:(language:kuery,query:''))"
        )

    def _build_g(self, time_from: str, time_to: str) -> str:
        return f"(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:{time_from},to:{time_to}))"

    def _build_dashboard_url(self, alert: dict) -> str:
        wazuh_id = self._rison_escape(alert.get("id", ""))
        if not wazuh_id:
            # Si no hay id, mandamos a general con 90d (sin duplicados)
            return (
                f"{DASHBOARD_BASE}/app/threat-hunting#/overview/?tab=general&tabView=events"
                f"&_a=(filters:!(),query:(language:kuery,query:''))"
                f"&_g={self._build_g(FINAL_TIME_FROM, FINAL_TIME_TO)}"
            )

        a_filter = self._build_filter_a(wazuh_id)

        # 1) Bloque wrapped EXACTO: &(_a=... )&(_g=... )
        wrapped = (
            f"&(_a={a_filter})"
            f"&(_g={self._build_g(WRAPPED_TIME_FROM, WRAPPED_TIME_TO)})"
        )

        # 2) Bloque final EXACTO: &_a=...&_g=...
        final = (
            f"&_a={a_filter}"
            f"&_g={self._build_g(FINAL_TIME_FROM, FINAL_TIME_TO)}"
        )

        # OJO: NO añadimos nunca _a/_g vacíos
        return (
            f"{DASHBOARD_BASE}/app/threat-hunting#/overview/?tab=general&tabView=events"
            f"{wrapped}"
            f"{final}"
        )

    def _make_payload(self, alert: dict) -> dict:
        rule = alert.get("rule", {}) or {}
        agent = alert.get("agent", {}) or {}
        data = alert.get("data", {}) or {}

        lvl = int(rule.get("level", 0))
        pr_txt, pr_clr = self._priority(lvl)

        desc = rule.get("description", "N/A")
        rid = str(rule.get("id", "N/A"))
        groups = ", ".join(rule.get("groups", []) or [])
        agent_name = agent.get("name", "manager")
        agent_ip = agent.get("ip", "N/A")
        ts = self._format_time(alert.get("timestamp", ""))

        vt_link = ""
        try:
            vt_link = (data.get("virustotal", {}) or {}).get("permalink", "") or ""
        except Exception:
            pass

        full_log = (alert.get("full_log") or "").strip() or "(N/A)"
        if len(full_log) > 900:
            full_log = full_log[:900] + "…"

        dashboard_url = self._build_dashboard_url(alert)

        facts = [
            {"title": "Level", "value": f"{pr_txt} ({lvl})"},
            {"title": "Rule ID", "value": rid},
            {"title": "Description", "value": desc},
            {"title": "Groups", "value": groups or "N/A"},
            {"title": "Agent", "value": f"{agent_name} ({agent_ip})"},
            {"title": "Timestamp", "value": ts},
            {"title": "Alert ID", "value": str(alert.get("id", "N/A"))},
        ]
        if vt_link:
            facts.append({"title": "VirusTotal", "value": vt_link})

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
                {"type": "FactSet", "facts": facts},
                {
                    "type": "TextBlock",
                    "text": full_log,
                    "wrap": True,
                    "spacing": "Small",
                    "isSubtle": True,
                    "fontType": "Monospace",
                },
            ],
            "actions": [
                {"type": "Action.OpenUrl", "title": "Dashboard", "url": dashboard_url}
            ],
        }

        if vt_link:
            adaptive_card["actions"].append(
                {"type": "Action.OpenUrl", "title": "VirusTotal", "url": vt_link}
            )

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
            self.logger.info(
                f"custom-teams: Skipped (alert level {alert_level} < configured {self.min_level})"
            )
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
