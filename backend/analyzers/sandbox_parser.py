"""Parser for sandbox analysis reports (Any.Run, Joe Sandbox, generic JSON)."""

import json
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class NetworkConnection:
    """Represents a network connection from sandbox analysis."""
    protocol: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    domain: Optional[str] = None


@dataclass
class ProcessInfo:
    """Represents a process from sandbox analysis."""
    pid: int
    name: str
    path: Optional[str] = None
    cmdline: Optional[str] = None
    parent_pid: Optional[int] = None


@dataclass
class FileOperation:
    """Represents a file operation from sandbox analysis."""
    operation: str  # create, write, delete, read
    path: str
    process: Optional[str] = None


class SandboxParser:
    """Parse sandbox analysis reports from various sources."""

    def __init__(self):
        """Initialize the parser."""
        self.supported_formats = ["anyrun", "joesandbox", "generic"]

    def parse(self, file_path: str) -> Dict:
        """
        Parse a sandbox report file.

        Args:
            file_path: Path to the report file (JSON or PDF)

        Returns:
            Normalized dictionary with analysis results
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        # Determine file type
        _, ext = os.path.splitext(file_path.lower())

        if ext == '.json':
            return self._parse_json_report(file_path)
        elif ext == '.pdf':
            return self._parse_pdf_report(file_path)
        else:
            return {"error": f"Unsupported file type: {ext}"}

    def _parse_json_report(self, file_path: str) -> Dict:
        """Parse a JSON sandbox report."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {str(e)}"}
        except Exception as e:
            return {"error": f"Failed to read file: {str(e)}"}

        # Detect report format
        report_format = self._detect_format(data)

        if report_format == "anyrun":
            return self._parse_anyrun(data)
        elif report_format == "joesandbox":
            return self._parse_joesandbox(data)
        else:
            return self._parse_generic(data)

    def _detect_format(self, data: Dict) -> str:
        """Detect the sandbox report format."""
        # Any.Run indicators
        if "analysis" in data and "content" in data.get("analysis", {}):
            return "anyrun"

        # Joe Sandbox indicators
        if "analysis" in data and "behavior" in data:
            return "joesandbox"

        if "generalinfo" in data or "fileinfo" in data:
            return "joesandbox"

        return "generic"

    def _parse_anyrun(self, data: Dict) -> Dict:
        """Parse Any.Run JSON report."""
        result = {
            "source": "anyrun",
            "sample_info": {},
            "verdict": None,
            "score": None,
            "processes": [],
            "network": [],
            "files": [],
            "registry": [],
            "iocs": [],
            "mitre_techniques": [],
            "screenshots": [],
            "raw_behaviors": []
        }

        analysis = data.get("analysis", {})
        content = analysis.get("content", {})

        # Sample info
        main_object = content.get("mainObject", {})
        result["sample_info"] = {
            "filename": main_object.get("filename"),
            "md5": main_object.get("hashes", {}).get("md5"),
            "sha1": main_object.get("hashes", {}).get("sha1"),
            "sha256": main_object.get("hashes", {}).get("sha256"),
            "file_type": main_object.get("type"),
            "size": main_object.get("size")
        }

        # Verdict and score
        scores = content.get("scores", {})
        result["verdict"] = scores.get("verdict", {}).get("verdict")
        result["score"] = scores.get("verdict", {}).get("threatLevel")

        # Processes
        for proc in content.get("processes", []):
            result["processes"].append({
                "pid": proc.get("pid"),
                "name": proc.get("name"),
                "path": proc.get("fileName"),
                "cmdline": proc.get("commandLine"),
                "parent_pid": proc.get("ppid")
            })

        # Network connections
        for conn in content.get("network", {}).get("connections", []):
            result["network"].append({
                "protocol": conn.get("protocol"),
                "dest_ip": conn.get("ip"),
                "dest_port": conn.get("port"),
                "domain": conn.get("domain")
            })

            # Add as IOC
            if conn.get("ip"):
                result["iocs"].append({
                    "type": "ip",
                    "value": conn.get("ip"),
                    "context": f"Network connection to port {conn.get('port')}"
                })
            if conn.get("domain"):
                result["iocs"].append({
                    "type": "domain",
                    "value": conn.get("domain"),
                    "context": "DNS resolution during analysis"
                })

        # HTTP requests
        for http in content.get("network", {}).get("http", []):
            result["network"].append({
                "type": "http",
                "method": http.get("method"),
                "url": http.get("url"),
                "host": http.get("host")
            })
            if http.get("url"):
                result["iocs"].append({
                    "type": "url",
                    "value": http.get("url"),
                    "context": "HTTP request during analysis"
                })

        # File operations
        for file_op in content.get("files", {}).get("created", []):
            result["files"].append({
                "operation": "create",
                "path": file_op.get("path"),
                "name": file_op.get("name")
            })

        # MITRE ATT&CK
        for technique in content.get("mitre", []):
            result["mitre_techniques"].append({
                "id": technique.get("id"),
                "name": technique.get("name"),
                "tactic": technique.get("tactic")
            })

        return result

    def _parse_joesandbox(self, data: Dict) -> Dict:
        """Parse Joe Sandbox JSON report."""
        result = {
            "source": "joesandbox",
            "sample_info": {},
            "verdict": None,
            "score": None,
            "processes": [],
            "network": [],
            "files": [],
            "registry": [],
            "iocs": [],
            "mitre_techniques": [],
            "signatures": [],
            "raw_behaviors": []
        }

        # General info
        general_info = data.get("generalinfo", data.get("analysis", {}).get("general", {}))
        file_info = data.get("fileinfo", data.get("analysis", {}).get("file", {}))

        result["sample_info"] = {
            "filename": general_info.get("target", {}).get("filename") or file_info.get("filename"),
            "md5": file_info.get("md5"),
            "sha1": file_info.get("sha1"),
            "sha256": file_info.get("sha256"),
            "file_type": file_info.get("filetype"),
            "size": file_info.get("filesize")
        }

        # Score
        detection = data.get("detection", data.get("analysis", {}).get("detection", {}))
        result["score"] = detection.get("score")
        result["verdict"] = "malicious" if (result["score"] or 0) >= 50 else "suspicious" if (result["score"] or 0) >= 25 else "clean"

        # Behavior analysis
        behavior = data.get("behavior", data.get("analysis", {}).get("behavior", {}))

        # Processes
        for proc in behavior.get("processes", []):
            result["processes"].append({
                "pid": proc.get("pid"),
                "name": proc.get("process_name"),
                "path": proc.get("image_path"),
                "cmdline": proc.get("command_line"),
                "parent_pid": proc.get("parent_pid")
            })

        # Network
        network = behavior.get("network", {})
        for conn in network.get("tcp", []) + network.get("udp", []):
            result["network"].append({
                "protocol": "tcp" if conn in network.get("tcp", []) else "udp",
                "dest_ip": conn.get("dst"),
                "dest_port": conn.get("dport"),
                "source_port": conn.get("sport")
            })
            if conn.get("dst"):
                result["iocs"].append({
                    "type": "ip",
                    "value": conn.get("dst"),
                    "context": f"Network connection to port {conn.get('dport')}"
                })

        # DNS
        for dns in network.get("dns", []):
            if dns.get("answers"):
                for answer in dns["answers"]:
                    if answer.get("data"):
                        result["iocs"].append({
                            "type": "ip",
                            "value": answer.get("data"),
                            "context": f"DNS resolution for {dns.get('request')}"
                        })
            if dns.get("request"):
                result["iocs"].append({
                    "type": "domain",
                    "value": dns.get("request"),
                    "context": "DNS query during analysis"
                })

        # HTTP requests
        for http in network.get("http", []):
            result["network"].append({
                "type": "http",
                "method": http.get("method"),
                "url": http.get("uri"),
                "host": http.get("host")
            })

        # Signatures
        for sig in data.get("signatures", data.get("analysis", {}).get("signatures", [])):
            result["signatures"].append({
                "name": sig.get("name"),
                "description": sig.get("description"),
                "severity": sig.get("severity"),
                "categories": sig.get("categories", [])
            })

        # MITRE ATT&CK
        mitre = data.get("mitre_attck", data.get("analysis", {}).get("mitre", []))
        if isinstance(mitre, list):
            for technique in mitre:
                result["mitre_techniques"].append({
                    "id": technique.get("id") or technique.get("technique_id"),
                    "name": technique.get("name") or technique.get("technique"),
                    "tactic": technique.get("tactic")
                })

        return result

    def _parse_generic(self, data: Dict) -> Dict:
        """Parse a generic JSON sandbox report."""
        result = {
            "source": "generic",
            "sample_info": {},
            "verdict": None,
            "score": None,
            "processes": [],
            "network": [],
            "files": [],
            "registry": [],
            "iocs": [],
            "mitre_techniques": [],
            "raw_data": data
        }

        # Try to extract common fields
        # Sample info - try various common keys
        for key in ["sample", "file", "target", "submission"]:
            if key in data:
                sample_data = data[key]
                result["sample_info"] = {
                    "filename": sample_data.get("filename") or sample_data.get("name"),
                    "md5": sample_data.get("md5"),
                    "sha1": sample_data.get("sha1"),
                    "sha256": sample_data.get("sha256"),
                    "file_type": sample_data.get("type") or sample_data.get("filetype"),
                    "size": sample_data.get("size") or sample_data.get("filesize")
                }
                break

        # Extract IOCs from common locations
        ioc_keys = ["iocs", "indicators", "ioc"]
        for key in ioc_keys:
            if key in data:
                iocs = data[key]
                if isinstance(iocs, list):
                    for ioc in iocs:
                        if isinstance(ioc, dict):
                            result["iocs"].append({
                                "type": ioc.get("type", "unknown"),
                                "value": ioc.get("value") or ioc.get("indicator"),
                                "context": ioc.get("context") or ioc.get("description")
                            })
                        elif isinstance(ioc, str):
                            result["iocs"].append({
                                "type": "unknown",
                                "value": ioc,
                                "context": "Extracted from report"
                            })

        # Extract network data
        network_keys = ["network", "connections", "traffic"]
        for key in network_keys:
            if key in data:
                network_data = data[key]
                if isinstance(network_data, list):
                    for conn in network_data:
                        if isinstance(conn, dict):
                            result["network"].append(conn)

        # Score/verdict
        result["score"] = data.get("score") or data.get("threat_score") or data.get("risk_score")
        result["verdict"] = data.get("verdict") or data.get("classification") or data.get("malware")

        return result

    def _parse_pdf_report(self, file_path: str) -> Dict:
        """Parse a PDF sandbox report using pdfplumber."""
        try:
            import pdfplumber
        except ImportError:
            return {"error": "pdfplumber not installed. Install with: pip install pdfplumber"}

        result = {
            "source": "pdf",
            "sample_info": {},
            "iocs": [],
            "text_content": "",
            "pages": []
        }

        try:
            with pdfplumber.open(file_path) as pdf:
                full_text = ""
                for i, page in enumerate(pdf.pages):
                    text = page.extract_text() or ""
                    full_text += text + "\n"
                    result["pages"].append({
                        "page_number": i + 1,
                        "text_length": len(text)
                    })

                result["text_content"] = full_text[:50000]  # Limit to 50KB

                # Extract IOCs from text using regex patterns
                from .ioc_extractor import IOCExtractor
                ioc_extractor = IOCExtractor()
                extracted_iocs = ioc_extractor.extract(full_text)

                for ioc_type, values in extracted_iocs.items():
                    for value in values:
                        result["iocs"].append({
                            "type": ioc_type,
                            "value": value,
                            "context": "Extracted from PDF report"
                        })

                # Try to extract sample info from text
                # Look for common patterns
                import re

                # MD5
                md5_match = re.search(r'MD5[:\s]+([a-fA-F0-9]{32})', full_text)
                if md5_match:
                    result["sample_info"]["md5"] = md5_match.group(1).lower()

                # SHA256
                sha256_match = re.search(r'SHA256[:\s]+([a-fA-F0-9]{64})', full_text)
                if sha256_match:
                    result["sample_info"]["sha256"] = sha256_match.group(1).lower()

                # Filename
                filename_match = re.search(r'(?:File ?[Nn]ame|Sample)[:\s]+([^\n\r]+)', full_text)
                if filename_match:
                    result["sample_info"]["filename"] = filename_match.group(1).strip()

        except Exception as e:
            result["error"] = f"Failed to parse PDF: {str(e)}"

        return result

    def normalize_report(self, parsed_data: Dict) -> Dict:
        """
        Normalize parsed report data to a standard format.

        Args:
            parsed_data: Parsed sandbox report data

        Returns:
            Normalized report dictionary
        """
        normalized = {
            "source": parsed_data.get("source", "unknown"),
            "analysis_time": datetime.utcnow().isoformat(),
            "sample": {
                "filename": None,
                "hashes": {
                    "md5": None,
                    "sha1": None,
                    "sha256": None
                },
                "type": None,
                "size": None
            },
            "verdict": {
                "classification": parsed_data.get("verdict"),
                "score": parsed_data.get("score"),
                "confidence": None
            },
            "indicators": {
                "iocs": parsed_data.get("iocs", []),
                "network": parsed_data.get("network", []),
                "files": parsed_data.get("files", []),
                "registry": parsed_data.get("registry", []),
                "processes": parsed_data.get("processes", [])
            },
            "mitre": parsed_data.get("mitre_techniques", []),
            "signatures": parsed_data.get("signatures", [])
        }

        # Fill in sample info
        sample_info = parsed_data.get("sample_info", {})
        normalized["sample"]["filename"] = sample_info.get("filename")
        normalized["sample"]["hashes"]["md5"] = sample_info.get("md5")
        normalized["sample"]["hashes"]["sha1"] = sample_info.get("sha1")
        normalized["sample"]["hashes"]["sha256"] = sample_info.get("sha256")
        normalized["sample"]["type"] = sample_info.get("file_type")
        normalized["sample"]["size"] = sample_info.get("size")

        return normalized
