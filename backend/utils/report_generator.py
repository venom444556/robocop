"""Report generation utilities for multiple output formats."""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportGenerator:
    """Generate analysis reports in multiple formats."""

    TLP_COLORS = {
        "TLP:WHITE": "#ffffff",
        "TLP:GREEN": "#33a02c",
        "TLP:AMBER": "#ff8c00",
        "TLP:RED": "#dc3545",
    }

    def __init__(self):
        """Initialize the report generator."""
        # Enable autoescape to prevent XSS from malicious IOC values
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
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
        template = self.jinja_env.get_template("report.html")
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
