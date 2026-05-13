import os
from collections import Counter
from datetime import datetime
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv


# Lädt die lokalen Einstellungen aus der .env-Datei.
# Die echte .env wird nicht auf GitHub hochgeladen.
load_dotenv()


def get_env_value(name: str) -> str:
    """
    Liest eine Pflichtvariable aus der .env-Datei.
    Wenn sie fehlt, wird eine klare Fehlermeldung ausgegeben.
    """
    value = os.getenv(name)

    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")

    return value


def get_verify_ssl() -> bool:
    """
    Prüft, ob SSL-Zertifikate verifiziert werden sollen.
    Im lokalen Wazuh-Lab wird meist false genutzt, weil selbstsignierte Zertifikate verwendet werden.
    """
    value = os.getenv("VERIFY_SSL", "false").lower()
    return value in ("true", "1", "yes")


def get_alert_limit() -> int:
    """
    Liest aus, wie viele Alerts maximal abgefragt werden sollen.
    Standardwert: 500.
    """
    value = os.getenv("ALERT_LIMIT", "500")

    try:
        return int(value)
    except ValueError:
        return 500


def fetch_alerts(
    indexer_url: str,
    indexer_user: str,
    indexer_password: str,
    alert_index: str,
    alert_limit: int,
    verify_ssl: bool
) -> dict:
    """
    Fragt Alerts aus dem Wazuh Indexer ab.

    Verwendeter Index:
    wazuh-alerts-*

    Es werden die neuesten Alerts nach @timestamp sortiert geladen.
    """
    url = f"{indexer_url}/{alert_index}/_search"

    query = {
        "size": alert_limit,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
        "_source": [
            "@timestamp",
            "agent.name",
            "agent.id",
            "rule.description",
            "rule.level",
            "rule.id",
            "rule.groups",
            "rule.mitre.tactic",
            "rule.mitre.technique",
            "location",
            "full_log"
        ],
        "query": {
            "match_all": {}
        }
    }

    response = requests.post(
        url,
        auth=(indexer_user, indexer_password),
        json=query,
        verify=verify_ssl,
        timeout=20
    )

    response.raise_for_status()
    return response.json()


def extract_alert_sources(search_response: dict) -> list:
    """
    Extrahiert die eigentlichen Alert-Daten aus der Indexer-Antwort.
    """
    hits = search_response.get("hits", {}).get("hits", [])
    return [hit.get("_source", {}) for hit in hits]


def get_total_alert_count(search_response: dict) -> int:
    """
    Liest die Gesamtzahl der gefundenen Alerts aus der Indexer-Antwort.
    """
    total = search_response.get("hits", {}).get("total", {})

    if isinstance(total, dict):
        return total.get("value", 0)

    if isinstance(total, int):
        return total

    return 0


def analyze_alerts(alerts: list) -> dict:
    """
    Erstellt einfache Auswertungen aus den Alerts.

    Ausgewertet werden:
    - Top Rule Descriptions
    - Rule Levels
    - Top Agents
    - MITRE-Techniken
    """
    rule_descriptions = Counter()
    rule_levels = Counter()
    agent_names = Counter()
    mitre_techniques = Counter()

    for alert in alerts:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        description = rule.get("description", "Unknown rule")
        level = rule.get("level", "unknown")
        agent_name = agent.get("name", "unknown")

        rule_descriptions[description] += 1
        rule_levels[str(level)] += 1
        agent_names[agent_name] += 1

        techniques = rule.get("mitre", {}).get("technique", [])

        if isinstance(techniques, list):
            for technique in techniques:
                mitre_techniques[technique] += 1
        elif isinstance(techniques, str):
            mitre_techniques[techniques] += 1

    return {
        "top_rules": rule_descriptions.most_common(10),
        "rule_levels": sorted(rule_levels.items(), key=lambda item: int(item[0]) if item[0].isdigit() else 0, reverse=True),
        "top_agents": agent_names.most_common(10),
        "mitre_techniques": mitre_techniques.most_common(10),
    }


def print_alert_report(total_alerts: int, loaded_alerts: int, analysis: dict) -> None:
    """
    Gibt den Alert-Report in der Konsole aus.
    """
    print()
    print("Wazuh Alert Summary")
    print("===================")
    print(f"Total alerts in index: {total_alerts}")
    print(f"Loaded alerts:         {loaded_alerts}")
    print()

    print("Top Rules")
    print("---------")
    for description, count in analysis["top_rules"]:
        print(f"- {description}: {count}")

    print()
    print("Rule Levels")
    print("-----------")
    for level, count in analysis["rule_levels"]:
        print(f"- Level {level}: {count}")

    print()
    print("Top Agents")
    print("----------")
    for agent, count in analysis["top_agents"]:
        print(f"- {agent}: {count}")

    print()
    print("MITRE Techniques")
    print("----------------")
    if analysis["mitre_techniques"]:
        for technique, count in analysis["mitre_techniques"]:
            print(f"- {technique}: {count}")
    else:
        print("- No MITRE techniques found in loaded alerts.")


def create_markdown_report(total_alerts: int, loaded_alerts: int, analysis: dict) -> Path:
    """
    Erstellt einen Markdown-Report im Ordner reports.
    """
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / "wazuh-alert-summary.md"

    lines = [
        "# Wazuh Alert Summary",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"- Total alerts in index: {total_alerts}",
        f"- Loaded alerts: {loaded_alerts}",
        "",
        "## Top Rules",
        "",
        "| Rule Description | Count |",
        "|---|---:|",
    ]

    for description, count in analysis["top_rules"]:
        lines.append(f"| {description} | {count} |")

    lines.extend([
        "",
        "## Rule Levels",
        "",
        "| Rule Level | Count |",
        "|---|---:|",
    ])

    for level, count in analysis["rule_levels"]:
        lines.append(f"| Level {level} | {count} |")

    lines.extend([
        "",
        "## Top Agents",
        "",
        "| Agent | Count |",
        "|---|---:|",
    ])

    for agent, count in analysis["top_agents"]:
        lines.append(f"| {agent} | {count} |")

    lines.extend([
        "",
        "## MITRE Techniques",
        "",
        "| MITRE Technique | Count |",
        "|---|---:|",
    ])

    if analysis["mitre_techniques"]:
        for technique, count in analysis["mitre_techniques"]:
            lines.append(f"| {technique} | {count} |")
    else:
        lines.append("| No MITRE techniques found | 0 |")

    report_path.write_text("\n".join(lines), encoding="utf-8")

    return report_path


def main() -> None:
    """
    Einstiegspunkt des Programms.
    """
    indexer_url = get_env_value("WAZUH_INDEXER_URL")
    indexer_user = get_env_value("WAZUH_INDEXER_USER")
    indexer_password = get_env_value("WAZUH_INDEXER_PASSWORD")
    alert_index = os.getenv("ALERT_INDEX", "wazuh-alerts-*")
    alert_limit = get_alert_limit()
    verify_ssl = get_verify_ssl()

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("Connecting to Wazuh Indexer...")
    print(f"Alert index: {alert_index}")
    print(f"Alert limit: {alert_limit}")

    search_response = fetch_alerts(
        indexer_url=indexer_url,
        indexer_user=indexer_user,
        indexer_password=indexer_password,
        alert_index=alert_index,
        alert_limit=alert_limit,
        verify_ssl=verify_ssl
    )

    alerts = extract_alert_sources(search_response)
    total_alerts = get_total_alert_count(search_response)
    analysis = analyze_alerts(alerts)

    print_alert_report(
        total_alerts=total_alerts,
        loaded_alerts=len(alerts),
        analysis=analysis
    )

    report_path = create_markdown_report(
        total_alerts=total_alerts,
        loaded_alerts=len(alerts),
        analysis=analysis
    )

    print()
    print(f"Markdown report created: {report_path}")


if __name__ == "__main__":
    main()
