from __future__ import annotations

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

SENSITIVE_FILE_CHECKS = [
    {
        "path": "/.git/HEAD",
        "name": "Git Repository",
        "risk": "critical",
        "recommendation": "Remove .git directory from production or block public access.",
    },
    {
        "path": "/.git/config",
        "name": "Git Config",
        "risk": "critical",
        "recommendation": "Remove .git directory from production or block public access.",
    },
    {
        "path": "/.env",
        "name": "Environment File",
        "risk": "critical",
        "recommendation": "Remove .env file from production and rotate all exposed secrets.",
    },
    {
        "path": "/.env.local",
        "name": "Local Environment File",
        "risk": "critical",
        "recommendation": "Remove .env.local file from production.",
    },
    {
        "path": "/.env.production",
        "name": "Production Environment File",
        "risk": "critical",
        "recommendation": "Remove .env.production from production.",
    },
    {
        "path": "/wp-config.php.bak",
        "name": "WordPress Config Backup",
        "risk": "high",
        "recommendation": "Remove backup files from production.",
    },
    {
        "path": "/wp-config.php~",
        "name": "WordPress Config Tilde Backup",
        "risk": "high",
        "recommendation": "Remove backup files from production.",
    },
    {
        "path": "/wp-config.php.save",
        "name": "WordPress Config Save",
        "risk": "high",
        "recommendation": "Remove backup files from production.",
    },
    {
        "path": "/database.sql",
        "name": "SQL Database Dump",
        "risk": "high",
        "recommendation": "Remove database dumps from production.",
    },
    {
        "path": "/dump.sql",
        "name": "SQL Dump File",
        "risk": "high",
        "recommendation": "Remove database dumps from production.",
    },
    {
        "path": "/db.sql",
        "name": "SQL Database File",
        "risk": "high",
        "recommendation": "Remove database dumps from production.",
    },
    {
        "path": "/backup.zip",
        "name": "ZIP Backup",
        "risk": "high",
        "recommendation": "Remove backup archives from production.",
    },
    {
        "path": "/backup.tar.gz",
        "name": "Tarball Backup",
        "risk": "high",
        "recommendation": "Remove backup archives from production.",
    },
    {
        "path": "/backup.sql.gz",
        "name": "Compressed SQL Backup",
        "risk": "high",
        "recommendation": "Remove backup archives from production.",
    },
    {
        "path": "/robots.txt",
        "name": "Robots.txt",
        "risk": "info",
        "recommendation": "Review robots.txt for hidden paths that may leak structure.",
    },
    {
        "path": "/sitemap.xml",
        "name": "Sitemap XML",
        "risk": "info",
        "recommendation": "Review sitemap for unintended URL exposure.",
    },
]


@register_plugin
class SensitiveFilesPlugin(OSINTPlugin):
    name = "sensitive-files"
    description = "Check for exposed sensitive files and backup data"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.85
    tags = ["files", "backup", "exposure", "sensitive"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[dict] = []

        try:
            domain = entity.value.strip().lower()
            base_url = f"https://{domain}"

            exposed_files: list[dict] = []

            for check in SENSITIVE_FILE_CHECKS:
                try:
                    url = f"{base_url}{check['path']}"
                    resp = requests.head(
                        url,
                        timeout=10,
                        allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0 (compatible; DeepLook/1.0)"},
                        verify=False,
                    )
                    if resp.status_code == 200:
                        exposed_files.append(
                            {
                                "path": check["path"],
                                "name": check["name"],
                                "risk": check["risk"],
                                "recommendation": check["recommendation"],
                            }
                        )
                except requests.RequestException:
                    continue

            if exposed_files:
                for ef in exposed_files:
                    findings.append(
                        {
                            "category": "Exposure Risk",
                            "check": f"Sensitive File: {ef['name']}",
                            "status": "fail",
                            "risk": ef["risk"],
                            "message": f"Sensitive file accessible at {ef['path']}",
                            "recommendation": ef["recommendation"],
                        }
                    )
                    entity.add_tag("sensitive-file-exposed")
            else:
                findings.append(
                    {
                        "category": "Exposure Risk",
                        "check": "Sensitive Files",
                        "status": "pass",
                        "risk": "info",
                        "message": "No exposed sensitive files or backups detected",
                        "recommendation": "",
                    }
                )

            result.metadata["findings"] = findings

            entity.add_provenance(
                source="sensitive-files",
                confidence=0.85,
                raw_data={"exposed_files": exposed_files},
            )

            workspace.add_entity(entity)
            result.add_entity(entity)
            result.raw_data = {"exposed_files": exposed_files}

        except Exception as e:
            result.add_warning(f"Sensitive files check failed: {e}")

        return result
