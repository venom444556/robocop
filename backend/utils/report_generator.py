"""Report generation utilities for multiple output formats."""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from jinja2 import Environment, BaseLoader, select_autoescape


class ReportGenerator:
    """Generate analysis reports in multiple formats."""

    TLP_COLORS = {
        "TLP:WHITE": "#ffffff",
        "TLP:GREEN": "#33a02c",
        "TLP:AMBER": "#ff8c00",
        "TLP:RED": "#dc3545",
    }

    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {{ submission_id }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .report-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 40px;
        }
        .tlp-banner {
            padding: 8px 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
            border-radius: 5px 5px 0 0;
            margin: -40px -40px 20px -40px;
            text-align: center;
        }
        .tlp-banner.tlp-white { background: #6c757d; color: #333; }
        .tlp-banner.tlp-green { background: #33a02c; }
        .tlp-banner.tlp-amber { background: #ff8c00; }
        .tlp-banner.tlp-red { background: #dc3545; }
        h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; margin-bottom: 20px; }
        h2 { color: #16213e; margin-top: 30px; margin-bottom: 15px; }
        h3 { color: #0f3460; margin-top: 20px; margin-bottom: 10px; }
        .metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .metadata p { margin: 5px 0; }
        .metadata strong { color: #16213e; }
        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.85em;
            color: white;
        }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; }
        .severity-informational { background: #17a2b8; }
        .severity-unknown { background: #6c757d; }
        .confidence-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: 600;
        }
        .confidence-high { background: #d4edda; color: #155724; }
        .confidence-medium { background: #fff3cd; color: #856404; }
        .confidence-low { background: #f8d7da; color: #721c24; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #16213e; color: white; }
        tr:hover { background: #f5f5f5; }
        .ioc-value { font-family: monospace; font-size: 0.9em; word-break: break-all; }
        .section { margin-bottom: 30px; }
        pre {
            background: #1a1a2e;
            color: #e94560;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
        }
        code { font-family: 'Fira Code', monospace; }
        .tag {
            display: inline-block;
            background: #e94560;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            margin: 2px;
        }
        .mitre-technique {
            background: #0f3460;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            margin: 3px;
            display: inline-block;
        }
        .mitre-validated { background: #155724; }
        .mitre-supposition { background: #856404; }
        .finding-card {
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid #6c757d;
        }
        .finding-card.finding-critical { border-left-color: #dc3545; }
        .finding-card.finding-high { border-left-color: #fd7e14; }
        .finding-card.finding-medium { border-left-color: #ffc107; }
        .finding-card.finding-low { border-left-color: #28a745; }
        .priority-p1 { color: #dc3545; font-weight: bold; }
        .priority-p2 { color: #fd7e14; font-weight: bold; }
        .priority-p3 { color: #ffc107; font-weight: bold; }
        .priority-p4 { color: #6c757d; font-weight: bold; }
        .evidence-item {
            background: #f8f9fa;
            padding: 5px 10px;
            border-radius: 3px;
            margin: 3px 0;
            font-size: 0.9em;
        }
        .narrative { white-space: pre-wrap; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="report-container">
        {% if tlp_marking %}
        <div class="tlp-banner tlp-{{ tlp_marking|lower|replace('tlp:', '') }}">
            {{ tlp_marking }} - Handle according to TLP protocol
        </div>
        {% endif %}

        <h1>Malware Analysis Report</h1>

        <div class="metadata">
            <p><strong>Report ID:</strong> {{ submission_id }}</p>
            <p><strong>Generated:</strong> {{ generated_at }}</p>
            <p><strong>Type:</strong> {{ submission_type }}</p>
            {% if filename %}<p><strong>Filename:</strong> {{ filename }}</p>{% endif %}
            {% if url %}<p><strong>URL:</strong> {{ url }}</p>{% endif %}
            {% if file_hash %}<p><strong>SHA256:</strong> <span class="ioc-value">{{ file_hash }}</span></p>{% endif %}
            <p><strong>Risk Level:</strong> <span class="severity-badge severity-{{ risk_level|lower }}">{{ risk_level|upper }}</span></p>
            {% if severity %}<p><strong>Severity:</strong> <span class="severity-badge severity-{{ severity|lower }}">{{ severity|upper }}</span></p>{% endif %}
            {% if confidence_score is not none %}<p><strong>Confidence Score:</strong> {{ confidence_score }}%</p>{% endif %}
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="narrative">{{ executive_summary }}</div>
        </div>

        {% if narrative %}
        <div class="section">
            <h2>Technical Analysis</h2>
            <div class="narrative">{{ narrative }}</div>
        </div>
        {% endif %}

        {% if threat_hunt_findings %}
        <div class="section">
            <h2>Threat Hunt Findings</h2>
            {% for finding in threat_hunt_findings %}
            <div class="finding-card finding-{{ finding.severity|lower }}">
                <h3>{{ finding.id }}: {{ finding.title }}</h3>
                <p>
                    <span class="severity-badge severity-{{ finding.severity|lower }}">{{ finding.severity }}</span>
                    <span class="confidence-badge confidence-{{ finding.confidence|lower }}">Confidence: {{ finding.confidence }}</span>
                    {% if finding.recommendation %}<span class="tag">{{ finding.recommendation }}</span>{% endif %}
                </p>
                {% if finding.description %}<p style="margin-top:10px;">{{ finding.description }}</p>{% endif %}
                {% if finding.evidence %}
                <div style="margin-top:10px;">
                    <strong>Evidence:</strong>
                    {% for e in finding.evidence %}
                    <div class="evidence-item">[{{ e.type }}] <code>{{ e.value }}</code> — {{ e.source }}</div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if mitre_validated or mitre_supposition %}
        <div class="section">
            <h2>MITRE ATT&CK Techniques</h2>
            {% if mitre_validation_stats %}
            <p><strong>Validation Rate:</strong> {{ mitre_validation_stats.validation_rate }}%
               ({{ mitre_validation_stats.validated_count }} validated / {{ mitre_validation_stats.total }} total)</p>
            {% endif %}
            {% if mitre_validated %}
            <h3>Confirmed Techniques</h3>
            {% for technique in mitre_validated %}
            <span class="mitre-technique mitre-validated">{{ technique.id }}: {{ technique.official_name or technique.name }}</span>
            {% endfor %}
            {% endif %}
            {% if mitre_supposition %}
            <h3>Unverified (LLM Supposition)</h3>
            {% for technique in mitre_supposition %}
            <span class="mitre-technique mitre-supposition">{{ technique.id }}: {{ technique.name }}</span>
            {% endfor %}
            {% endif %}
        </div>
        {% elif mitre_techniques %}
        <div class="section">
            <h2>MITRE ATT&CK Techniques</h2>
            {% for technique in mitre_techniques %}
            <span class="mitre-technique">{{ technique.id }}: {{ technique.name }}</span>
            {% endfor %}
        </div>
        {% endif %}

        {% if iocs %}
        <div class="section">
            <h2>Indicators of Compromise</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Context</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ioc in iocs[:50] %}
                    <tr>
                        <td>{{ ioc.type }}</td>
                        <td class="ioc-value">{{ ioc.value }}</td>
                        <td>{{ ioc.context or '-' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% if iocs|length > 50 %}
            <p><em>Showing 50 of {{ iocs|length }} IOCs. See JSON report for complete list.</em></p>
            {% endif %}
        </div>
        {% endif %}

        {% if investigation_plan %}
        <div class="section">
            <h2>Investigation & Response Plan</h2>
            {% if investigation_plan.investigation_steps %}
            <h3>Investigation Steps</h3>
            <table>
                <thead><tr><th>Priority</th><th>Action</th><th>Rationale</th></tr></thead>
                <tbody>
                {% for step in investigation_plan.investigation_steps %}
                <tr>
                    <td><span class="priority-{{ step.priority|lower }}">{{ step.priority }}</span></td>
                    <td>{{ step.action }}</td>
                    <td>{{ step.rationale or '-' }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% endif %}
            {% if investigation_plan.containment_actions %}
            <h3>Containment Actions</h3>
            <table>
                <thead><tr><th>Priority</th><th>Action</th><th>Scope</th></tr></thead>
                <tbody>
                {% for action in investigation_plan.containment_actions %}
                <tr>
                    <td><span class="priority-{{ action.priority|lower }}">{{ action.priority }}</span></td>
                    <td>{{ action.action }}</td>
                    <td>{{ action.scope or '-' }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% endif %}
            {% if investigation_plan.eradication_procedures %}
            <h3>Eradication & Recovery</h3>
            <ul>
                {% for step in investigation_plan.eradication_procedures %}
                <li>{{ step.action }}</li>
                {% endfor %}
            </ul>
            {% endif %}
            {% if investigation_plan.analyst_notes %}
            <p><strong>Analyst Notes:</strong> {{ investigation_plan.analyst_notes }}</p>
            {% endif %}
        </div>
        {% endif %}

        {% if cve_data %}
        <div class="section">
            <h2>CVE Intelligence</h2>
            <table>
                <thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Description</th></tr></thead>
                <tbody>
                {% for cve in cve_data[:20] %}
                <tr>
                    <td><strong>{{ cve.cve_id }}</strong></td>
                    <td>{{ cve.cvss_score or 'N/A' }}</td>
                    <td>{{ cve.cvss_severity or 'N/A' }}</td>
                    <td>{{ cve.description[:200] }}{% if cve.description|length > 200 %}...{% endif %}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if recommendations %}
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                {% for rec in recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        <div class="footer">
            <p>Generated by Malware Analysis Platform</p>
            <p>Report Time: {{ generated_at }}</p>
            {% if tlp_marking %}<p>Classification: {{ tlp_marking }}</p>{% endif %}
        </div>
    </div>
</body>
</html>
"""

    def __init__(self):
        """Initialize the report generator."""
        # Enable autoescape to prevent XSS from malicious IOC values
        self.jinja_env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(default=True, default_for_string=True)
        )

    def generate(self, format: str, submission: Any, analysis_results: List[Any],
                 iocs: List[Any], enrichment_data: Dict, narrative: str = "",
                 extra_data: Optional[Dict] = None) -> str:
        """
        Generate a report in the specified format.

        Args:
            format: Output format (json, html, pdf)
            submission: Submission object
            analysis_results: Analysis result objects
            iocs: IOC objects
            enrichment_data: Enrichment data dictionary
            narrative: Claude-generated narrative
            extra_data: Optional dict with enriched data (mitre_validation,
                        investigation_plan, threat_hunt_findings, cve_data, etc.)

        Returns:
            Report content as string (or bytes for PDF)
        """
        extra = extra_data or {}
        if format == "json":
            return self._generate_json(submission, analysis_results, iocs, enrichment_data, narrative, extra)
        elif format == "html":
            return self._generate_html(submission, analysis_results, iocs, enrichment_data, narrative, extra)
        elif format == "pdf":
            return self._generate_pdf(submission, analysis_results, iocs, enrichment_data, narrative, extra)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_json(self, submission, analysis_results, iocs, enrichment_data, narrative,
                        extra: Dict = None) -> str:
        """Generate JSON report."""
        extra = extra or {}

        # Get severity/tlp from submission if available
        severity = None
        tlp = None
        confidence = None
        if hasattr(submission, 'severity') and submission.severity:
            severity = submission.severity.value if hasattr(submission.severity, 'value') else str(submission.severity)
        if hasattr(submission, 'tlp_marking') and submission.tlp_marking:
            tlp = submission.tlp_marking.value if hasattr(submission.tlp_marking, 'value') else str(submission.tlp_marking)
        if hasattr(submission, 'confidence_score'):
            confidence = submission.confidence_score

        report_data = {
            "report_metadata": {
                "submission_id": submission.id,
                "generated_at": datetime.utcnow().isoformat(),
                "format": "json",
                "version": "2.0",
                "severity": severity,
                "tlp_marking": tlp,
                "confidence_score": confidence,
            },
            "submission": {
                "id": submission.id,
                "type": submission.type.value if hasattr(submission.type, 'value') else str(submission.type),
                "filename": submission.filename,
                "url": submission.original_url,
                "file_hash_sha256": submission.file_hash_sha256,
                "status": submission.status.value if hasattr(submission.status, 'value') else str(submission.status),
                "created_at": submission.created_at.isoformat() if submission.created_at else None,
                "completed_at": submission.completed_at.isoformat() if submission.completed_at else None
            },
            "analysis_results": [
                {
                    "analyzer": r.analyzer,
                    "results": r.results_json,
                    "created_at": r.created_at.isoformat() if r.created_at else None
                }
                for r in analysis_results
            ],
            "iocs": [
                {
                    "type": i.type.value if hasattr(i.type, 'value') else str(i.type),
                    "value": i.value,
                    "context": i.context
                }
                for i in iocs
            ],
            "enrichment": enrichment_data,
            "narrative": narrative,
        }

        # Add enriched sections from extra_data
        if extra.get("mitre_validation"):
            report_data["mitre_validation"] = extra["mitre_validation"]
        if extra.get("investigation_plan"):
            report_data["investigation_plan"] = extra["investigation_plan"]
        if extra.get("threat_hunt_findings"):
            report_data["threat_hunt_findings"] = extra["threat_hunt_findings"]
        if extra.get("cve_data"):
            report_data["cve_data"] = extra["cve_data"]

        return json.dumps(report_data, indent=2, default=str)

    def _generate_html(self, submission, analysis_results, iocs, enrichment_data, narrative,
                        extra: Dict = None) -> str:
        """Generate HTML report."""
        extra = extra or {}

        # Extract data for template
        risk_level = "medium"  # Default
        mitre_techniques = []
        executive_summary = ""
        recommendations = []

        for result in analysis_results:
            results_json = result.results_json
            if isinstance(results_json, dict):
                if results_json.get("risk_level"):
                    risk_level = results_json["risk_level"]
                if results_json.get("mitre_techniques"):
                    mitre_techniques.extend(results_json["mitre_techniques"])

        # Parse narrative for sections if it's structured
        if "Executive Summary" in narrative:
            parts = narrative.split("##")
            for part in parts:
                if "Executive Summary" in part:
                    executive_summary = part.replace("Executive Summary", "").strip()
                elif "Recommendation" in part:
                    rec_text = part.replace("Recommendations", "").strip()
                    recommendations = [r.strip("- ").strip() for r in rec_text.split("\n") if r.strip().startswith("-")]

        if not executive_summary:
            executive_summary = narrative[:1000] if narrative else "No summary available."

        # Prepare IOC data
        ioc_data = [
            {
                "type": i.type.value if hasattr(i.type, 'value') else str(i.type),
                "value": i.value,
                "context": i.context
            }
            for i in iocs
        ]

        # Extract enriched data for template
        severity = None
        if hasattr(submission, 'severity') and submission.severity:
            severity = submission.severity.value if hasattr(submission.severity, 'value') else str(submission.severity)

        tlp_marking = None
        if hasattr(submission, 'tlp_marking') and submission.tlp_marking:
            tlp_marking = submission.tlp_marking.value if hasattr(submission.tlp_marking, 'value') else str(submission.tlp_marking)

        confidence_score = getattr(submission, 'confidence_score', None)

        mitre_validation = extra.get("mitre_validation", {})
        mitre_validated = mitre_validation.get("validated", [])
        mitre_supposition = mitre_validation.get("supposition", [])
        mitre_validation_stats = mitre_validation.get("stats")

        threat_hunt = extra.get("threat_hunt_findings", {})
        threat_hunt_findings = threat_hunt.get("findings", []) if isinstance(threat_hunt, dict) else []

        investigation = extra.get("investigation_plan", {})
        investigation_plan = investigation.get("investigation_plan") if isinstance(investigation, dict) else None

        cve_data = extra.get("cve_data", [])

        # Render template
        template = self.jinja_env.from_string(self.HTML_TEMPLATE)
        html = template.render(
            submission_id=submission.id,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            submission_type=submission.type.value if hasattr(submission.type, 'value') else str(submission.type),
            filename=submission.filename,
            url=submission.original_url,
            file_hash=submission.file_hash_sha256,
            risk_level=risk_level,
            severity=severity,
            tlp_marking=tlp_marking,
            confidence_score=confidence_score,
            executive_summary=executive_summary,
            narrative=narrative,
            mitre_techniques=mitre_techniques[:20],
            mitre_validated=mitre_validated,
            mitre_supposition=mitre_supposition,
            mitre_validation_stats=mitre_validation_stats,
            threat_hunt_findings=threat_hunt_findings,
            investigation_plan=investigation_plan,
            cve_data=cve_data,
            iocs=ioc_data,
            recommendations=recommendations[:10]
        )

        return html

    def _generate_pdf(self, submission, analysis_results, iocs, enrichment_data, narrative,
                      extra: Dict = None) -> str:
        """Generate PDF report using WeasyPrint."""
        # First generate HTML
        html_content = self._generate_html(submission, analysis_results, iocs, enrichment_data, narrative, extra)

        try:
            from weasyprint import HTML
            pdf_bytes = HTML(string=html_content).write_pdf()
            # Return as base64 for storage
            import base64
            return base64.b64encode(pdf_bytes).decode('utf-8')
        except ImportError:
            # WeasyPrint not available, return HTML instead
            return html_content
        except Exception as e:
            # If PDF generation fails, return error in JSON
            return json.dumps({"error": f"PDF generation failed: {str(e)}", "html_fallback": html_content})

    def generate_ioc_export(self, iocs: List[Any], format: str = "csv") -> str:
        """
        Export IOCs in various formats.

        Args:
            iocs: List of IOC objects
            format: Export format (csv, stix, misp)

        Returns:
            Exported IOC data
        """
        if format == "csv":
            return self._export_csv(iocs)
        elif format == "stix":
            return self._export_stix(iocs)
        elif format == "misp":
            return self._export_misp(iocs)
        else:
            raise ValueError(f"Unsupported IOC export format: {format}")

    def _export_csv(self, iocs: List[Any]) -> str:
        """Export IOCs as CSV."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Value", "Context", "Defanged"])

        for ioc in iocs:
            ioc_type = ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type)
            value = ioc.value
            context = ioc.context or ""

            # Defang for safe sharing
            defanged = self._defang(value, ioc_type)

            writer.writerow([ioc_type, value, context, defanged])

        return output.getvalue()

    def _export_stix(self, iocs: List[Any]) -> str:
        """Export IOCs as STIX 2.1 bundle."""
        import uuid

        stix_objects = []

        for ioc in iocs:
            ioc_type = ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type)
            value = ioc.value

            stix_type = self._map_to_stix_type(ioc_type)
            if not stix_type:
                continue

            stix_object = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "pattern": self._create_stix_pattern(ioc_type, value),
                "pattern_type": "stix",
                "valid_from": datetime.utcnow().isoformat() + "Z",
                "labels": ["malicious-activity"]
            }
            stix_objects.append(stix_object)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects
        }

        return json.dumps(bundle, indent=2)

    def _export_misp(self, iocs: List[Any]) -> str:
        """Export IOCs as MISP event format."""
        import uuid

        attributes = []

        for ioc in iocs:
            ioc_type = ioc.type.value if hasattr(ioc.type, 'value') else str(ioc.type)
            value = ioc.value

            misp_type = self._map_to_misp_type(ioc_type)
            if not misp_type:
                continue

            attribute = {
                "uuid": str(uuid.uuid4()),
                "type": misp_type,
                "value": value,
                "category": self._get_misp_category(ioc_type),
                "to_ids": True,
                "comment": ioc.context or ""
            }
            attributes.append(attribute)

        event = {
            "Event": {
                "uuid": str(uuid.uuid4()),
                "info": "Malware Analysis Report IOCs",
                "date": datetime.utcnow().strftime("%Y-%m-%d"),
                "threat_level_id": "2",
                "analysis": "2",
                "Attribute": attributes
            }
        }

        return json.dumps(event, indent=2)

    def _defang(self, value: str, ioc_type: str) -> str:
        """Defang an IOC for safe sharing."""
        if ioc_type in ["ip", "domain"]:
            return value.replace(".", "[.]")
        elif ioc_type == "url":
            return value.replace("http", "hxxp").replace(".", "[.]")
        elif ioc_type == "email":
            return value.replace("@", "[@]").replace(".", "[.]")
        return value

    def _map_to_stix_type(self, ioc_type: str) -> Optional[str]:
        """Map IOC type to STIX indicator type."""
        mapping = {
            "ip": "ipv4-addr",
            "domain": "domain-name",
            "url": "url",
            "hash_md5": "file",
            "hash_sha1": "file",
            "hash_sha256": "file",
            "email": "email-addr"
        }
        return mapping.get(ioc_type)

    def _create_stix_pattern(self, ioc_type: str, value: str) -> str:
        """Create STIX pattern for an IOC."""
        if ioc_type == "ip":
            return f"[ipv4-addr:value = '{value}']"
        elif ioc_type == "domain":
            return f"[domain-name:value = '{value}']"
        elif ioc_type == "url":
            return f"[url:value = '{value}']"
        elif ioc_type == "hash_md5":
            return f"[file:hashes.MD5 = '{value}']"
        elif ioc_type == "hash_sha1":
            return f"[file:hashes.'SHA-1' = '{value}']"
        elif ioc_type == "hash_sha256":
            return f"[file:hashes.'SHA-256' = '{value}']"
        elif ioc_type == "email":
            return f"[email-addr:value = '{value}']"
        return f"[artifact:payload_bin = '{value}']"

    def _map_to_misp_type(self, ioc_type: str) -> Optional[str]:
        """Map IOC type to MISP attribute type."""
        mapping = {
            "ip": "ip-dst",
            "domain": "domain",
            "url": "url",
            "hash_md5": "md5",
            "hash_sha1": "sha1",
            "hash_sha256": "sha256",
            "email": "email-src",
            "filename": "filename"
        }
        return mapping.get(ioc_type)

    def _get_misp_category(self, ioc_type: str) -> str:
        """Get MISP category for an IOC type."""
        categories = {
            "ip": "Network activity",
            "domain": "Network activity",
            "url": "Network activity",
            "hash_md5": "Payload delivery",
            "hash_sha1": "Payload delivery",
            "hash_sha256": "Payload delivery",
            "email": "Payload delivery",
            "filename": "Payload delivery"
        }
        return categories.get(ioc_type, "External analysis")
