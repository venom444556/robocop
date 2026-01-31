"""Report generation utilities for multiple output formats."""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from jinja2 import Environment, BaseLoader, select_autoescape


class ReportGenerator:
    """Generate analysis reports in multiple formats."""

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
        h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; margin-bottom: 20px; }
        h2 { color: #16213e; margin-top: 30px; margin-bottom: 15px; }
        h3 { color: #0f3460; margin-top: 20px; margin-bottom: 10px; }
        .metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .metadata p { margin: 5px 0; }
        .metadata strong { color: #16213e; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
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
        <h1>🔬 Malware Analysis Report</h1>

        <div class="metadata">
            <p><strong>Report ID:</strong> {{ submission_id }}</p>
            <p><strong>Generated:</strong> {{ generated_at }}</p>
            <p><strong>Type:</strong> {{ submission_type }}</p>
            {% if filename %}<p><strong>Filename:</strong> {{ filename }}</p>{% endif %}
            {% if url %}<p><strong>URL:</strong> {{ url }}</p>{% endif %}
            {% if file_hash %}<p><strong>SHA256:</strong> <span class="ioc-value">{{ file_hash }}</span></p>{% endif %}
            <p><strong>Risk Level:</strong> <span class="severity-{{ risk_level|lower }}">{{ risk_level|upper }}</span></p>
        </div>

        <div class="section">
            <h2>📋 Executive Summary</h2>
            <div class="narrative">{{ executive_summary }}</div>
        </div>

        {% if narrative %}
        <div class="section">
            <h2>📊 Technical Analysis</h2>
            <div class="narrative">{{ narrative }}</div>
        </div>
        {% endif %}

        {% if mitre_techniques %}
        <div class="section">
            <h2>🎯 MITRE ATT&CK Techniques</h2>
            {% for technique in mitre_techniques %}
            <span class="mitre-technique">{{ technique.id }}: {{ technique.name }}</span>
            {% endfor %}
        </div>
        {% endif %}

        {% if iocs %}
        <div class="section">
            <h2>🔍 Indicators of Compromise</h2>
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

        {% if recommendations %}
        <div class="section">
            <h2>💡 Recommendations</h2>
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
                 iocs: List[Any], enrichment_data: Dict, narrative: str = "") -> str:
        """
        Generate a report in the specified format.

        Args:
            format: Output format (json, html, pdf)
            submission: Submission object
            analysis_results: Analysis result objects
            iocs: IOC objects
            enrichment_data: Enrichment data dictionary
            narrative: Claude-generated narrative

        Returns:
            Report content as string (or bytes for PDF)
        """
        if format == "json":
            return self._generate_json(submission, analysis_results, iocs, enrichment_data, narrative)
        elif format == "html":
            return self._generate_html(submission, analysis_results, iocs, enrichment_data, narrative)
        elif format == "pdf":
            return self._generate_pdf(submission, analysis_results, iocs, enrichment_data, narrative)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_json(self, submission, analysis_results, iocs, enrichment_data, narrative) -> str:
        """Generate JSON report."""
        report_data = {
            "report_metadata": {
                "submission_id": submission.id,
                "generated_at": datetime.utcnow().isoformat(),
                "format": "json",
                "version": "1.0"
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
            "narrative": narrative
        }

        return json.dumps(report_data, indent=2, default=str)

    def _generate_html(self, submission, analysis_results, iocs, enrichment_data, narrative) -> str:
        """Generate HTML report."""
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
            executive_summary=executive_summary,
            narrative=narrative,
            mitre_techniques=mitre_techniques[:20],
            iocs=ioc_data,
            recommendations=recommendations[:10]
        )

        return html

    def _generate_pdf(self, submission, analysis_results, iocs, enrichment_data, narrative) -> str:
        """Generate PDF report using WeasyPrint."""
        # First generate HTML
        html_content = self._generate_html(submission, analysis_results, iocs, enrichment_data, narrative)

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
