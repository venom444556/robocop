"""Script analyzer for detecting malicious patterns and behaviors."""

import re
import ast
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class AnalysisResult:
    """Result of script analysis."""
    script_type: str
    risk_level: str  # low, medium, high, critical
    risk_score: int  # 0-100
    behaviors: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_patterns: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    summary: str = ""


class ScriptAnalyzer:
    """Analyze scripts for malicious behaviors and patterns."""

    def __init__(self):
        """Initialize analyzer with detection patterns."""
        self._init_patterns()

    def _init_patterns(self):
        """Initialize detection patterns for various script types."""
        # PowerShell suspicious patterns
        self.ps_patterns = {
            "download_execution": {
                "patterns": [
                    r'(?:Invoke-WebRequest|iwr|wget|curl).*(?:Invoke-Expression|iex)',
                    r'(?:Net\.WebClient).*(?:DownloadString|DownloadFile).*(?:iex|Invoke-Expression)',
                    r'(?:DownloadString|DownloadFile).*Start-Process',
                    r'Invoke-Expression.*http',
                ],
                "description": "Downloads and executes remote content",
                "risk": 90,
                "mitre": {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}
            },
            "base64_execution": {
                "patterns": [
                    r'-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]+',
                    r'FromBase64String.*iex',
                    r'\[Convert\]::FromBase64String',
                ],
                "description": "Executes Base64 encoded content",
                "risk": 70,
                "mitre": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"}
            },
            "credential_access": {
                "patterns": [
                    r'Mimikatz|Invoke-Mimikatz',
                    r'Get-Credential',
                    r'SecureString.*Password',
                    r'HKLM:\\SAM|HKLM:\\SECURITY',
                    r'lsass\.exe',
                ],
                "description": "Attempts to access credentials",
                "risk": 95,
                "mitre": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"}
            },
            "persistence": {
                "patterns": [
                    r'New-ItemProperty.*Run',
                    r'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    r'schtasks.*\/create',
                    r'Register-ScheduledTask',
                    r'New-Service',
                ],
                "description": "Establishes persistence mechanism",
                "risk": 85,
                "mitre": {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"}
            },
            "defense_evasion": {
                "patterns": [
                    r'Set-MpPreference.*-DisableRealtimeMonitoring',
                    r'Stop-Service.*WinDefend',
                    r'Remove-Item.*-Force.*\.log',
                    r'Clear-EventLog',
                    r'-ExecutionPolicy\s+Bypass',
                    r'Add-MpPreference.*-ExclusionPath',
                ],
                "description": "Attempts to evade security controls",
                "risk": 80,
                "mitre": {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"}
            },
            "lateral_movement": {
                "patterns": [
                    r'Enter-PSSession',
                    r'Invoke-Command.*-ComputerName',
                    r'New-PSSession',
                    r'Copy-Item.*\\\\',
                    r'net\s+use.*\\\\',
                ],
                "description": "Attempts lateral movement",
                "risk": 85,
                "mitre": {"id": "T1021.006", "name": "Windows Remote Management", "tactic": "Lateral Movement"}
            },
            "data_exfiltration": {
                "patterns": [
                    r'Compress-Archive.*\.zip',
                    r'Send-MailMessage',
                    r'Invoke-RestMethod.*POST',
                    r'[System.Net.WebClient].*Upload',
                ],
                "description": "Potential data exfiltration",
                "risk": 75,
                "mitre": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}
            },
            "reconnaissance": {
                "patterns": [
                    r'Get-ADUser|Get-ADComputer|Get-ADGroup',
                    r'Get-WmiObject.*Win32_',
                    r'systeminfo|ipconfig|whoami|net\s+user',
                    r'\[System\.Environment\]::',
                ],
                "description": "System/network reconnaissance",
                "risk": 50,
                "mitre": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"}
            },
        }

        # JavaScript suspicious patterns
        self.js_patterns = {
            "eval_execution": {
                "patterns": [
                    r'eval\s*\(',
                    r'new\s+Function\s*\(',
                    r'setTimeout\s*\([^,]+,[^)]+\)',
                    r'setInterval\s*\([^,]+,[^)]+\)',
                ],
                "description": "Dynamic code execution",
                "risk": 60,
                "mitre": {"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}
            },
            "obfuscation": {
                "patterns": [
                    r'\\x[0-9a-fA-F]{2}',
                    r'\\u[0-9a-fA-F]{4}',
                    r'unescape\s*\(',
                    r'atob\s*\(',
                    r'String\.fromCharCode',
                ],
                "description": "Code obfuscation detected",
                "risk": 55,
                "mitre": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"}
            },
            "network_activity": {
                "patterns": [
                    r'XMLHttpRequest',
                    r'fetch\s*\(',
                    r'\.ajax\s*\(',
                    r'WebSocket',
                ],
                "description": "Network communication",
                "risk": 40,
                "mitre": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}
            },
            "data_theft": {
                "patterns": [
                    r'document\.cookie',
                    r'localStorage',
                    r'sessionStorage',
                    r'\.getItem\s*\(',
                ],
                "description": "Accesses stored data",
                "risk": 65,
                "mitre": {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access"}
            },
            "dom_manipulation": {
                "patterns": [
                    r'document\.write',
                    r'\.innerHTML\s*=',
                    r'\.outerHTML\s*=',
                    r'\.insertAdjacentHTML',
                ],
                "description": "DOM manipulation (potential XSS)",
                "risk": 50,
                "mitre": {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"}
            },
        }

        # VBScript suspicious patterns
        self.vbs_patterns = {
            "wscript_shell": {
                "patterns": [
                    r'WScript\.Shell',
                    r'\.Run\s*\(',
                    r'\.Exec\s*\(',
                    r'Shell\.Application',
                ],
                "description": "Command execution via WScript",
                "risk": 75,
                "mitre": {"id": "T1059.005", "name": "Visual Basic", "tactic": "Execution"}
            },
            "file_operations": {
                "patterns": [
                    r'Scripting\.FileSystemObject',
                    r'\.CreateTextFile',
                    r'\.OpenTextFile',
                    r'\.CopyFile|\.MoveFile|\.DeleteFile',
                ],
                "description": "File system operations",
                "risk": 60,
                "mitre": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}
            },
            "network_download": {
                "patterns": [
                    r'MSXML2\.XMLHTTP',
                    r'Microsoft\.XMLHTTP',
                    r'\.Open\s*"GET"',
                    r'\.responseBody|\.responseText',
                    r'ADODB\.Stream',
                ],
                "description": "Downloads content from network",
                "risk": 70,
                "mitre": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}
            },
            "registry_operations": {
                "patterns": [
                    r'\.RegWrite',
                    r'\.RegRead',
                    r'\.RegDelete',
                    r'HKEY_|HKLM|HKCU',
                ],
                "description": "Registry operations",
                "risk": 65,
                "mitre": {"id": "T1112", "name": "Modify Registry", "tactic": "Defense Evasion"}
            },
        }

        # Batch/CMD suspicious patterns
        self.batch_patterns = {
            "download_execution": {
                "patterns": [
                    r'certutil.*-urlcache.*-split.*-f',
                    r'bitsadmin.*\/transfer',
                    r'powershell.*downloadstring',
                    r'curl.*-o|wget.*-O',
                ],
                "description": "Downloads and potentially executes content",
                "risk": 80,
                "mitre": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}
            },
            "persistence": {
                "patterns": [
                    r'reg\s+add.*\\Run',
                    r'schtasks\s+\/create',
                    r'sc\s+create',
                ],
                "description": "Establishes persistence",
                "risk": 85,
                "mitre": {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"}
            },
            "defense_evasion": {
                "patterns": [
                    r'attrib\s+\+h',
                    r'del\s+\/f.*\.log',
                    r'wevtutil\s+cl',
                    r'netsh\s+advfirewall\s+set',
                ],
                "description": "Attempts to evade detection",
                "risk": 70,
                "mitre": {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"}
            },
        }

    def analyze(self, content: str, filename: str = "") -> Dict:
        """
        Analyze script content for malicious behaviors.

        Args:
            content: Script content to analyze
            filename: Optional filename for determining script type

        Returns:
            Dictionary with analysis results
        """
        script_type = self._detect_script_type(content, filename)
        behaviors = []
        suspicious_patterns = []
        mitre_techniques = []
        total_risk = 0
        pattern_count = 0

        # Select patterns based on script type
        patterns = self._get_patterns_for_type(script_type)

        for category, pattern_info in patterns.items():
            for pattern in pattern_info["patterns"]:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    pattern_count += 1
                    total_risk += pattern_info["risk"]

                    behaviors.append({
                        "category": category,
                        "description": pattern_info["description"],
                        "matches": matches[:5],  # Limit matches
                        "risk_contribution": pattern_info["risk"]
                    })

                    if pattern_info.get("mitre"):
                        mitre_techniques.append(pattern_info["mitre"])

                    suspicious_patterns.append({
                        "pattern": pattern,
                        "category": category,
                        "match_count": len(matches)
                    })

        # Calculate final risk score
        if pattern_count > 0:
            risk_score = min(100, total_risk // pattern_count + (pattern_count * 5))
        else:
            risk_score = 0

        risk_level = self._get_risk_level(risk_score)

        # Generate summary
        summary = self._generate_summary(script_type, behaviors, mitre_techniques, risk_level)

        return {
            "script_type": script_type,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "behaviors": behaviors,
            "suspicious_patterns": suspicious_patterns,
            "mitre_techniques": list({t["id"]: t for t in mitre_techniques}.values()),
            "summary": summary,
            "line_count": len(content.splitlines()),
            "char_count": len(content)
        }

    def _detect_script_type(self, content: str, filename: str) -> str:
        """Detect the type of script based on content and filename."""
        filename_lower = filename.lower()

        # Check by extension first
        if filename_lower.endswith('.ps1') or filename_lower.endswith('.psm1'):
            return "powershell"
        elif filename_lower.endswith('.js'):
            return "javascript"
        elif filename_lower.endswith('.vbs') or filename_lower.endswith('.vbe'):
            return "vbscript"
        elif filename_lower.endswith('.bat') or filename_lower.endswith('.cmd'):
            return "batch"
        elif filename_lower.endswith('.py'):
            return "python"
        elif filename_lower.endswith('.sh'):
            return "bash"

        # Content-based detection
        content_lower = content.lower()

        # PowerShell indicators
        if any(ind in content_lower for ind in ['$psversiontable', 'invoke-', 'get-wmiobject', '[system.', 'new-object']):
            return "powershell"

        # VBScript indicators
        if any(ind in content_lower for ind in ['wscript.', 'createobject', 'dim ', 'sub ', 'function ']):
            if 'function(' not in content_lower:  # Not JavaScript
                return "vbscript"

        # JavaScript indicators
        if any(ind in content_lower for ind in ['function(', 'var ', 'const ', 'let ', 'document.', 'window.']):
            return "javascript"

        # Batch indicators
        if any(ind in content_lower for ind in ['@echo off', 'echo.', 'goto ', 'set /a', '%~']):
            return "batch"

        # Python indicators
        if any(ind in content_lower for ind in ['import ', 'def ', 'class ', 'if __name__']):
            return "python"

        return "unknown"

    def _get_patterns_for_type(self, script_type: str) -> Dict:
        """Get detection patterns for a specific script type."""
        pattern_map = {
            "powershell": self.ps_patterns,
            "javascript": self.js_patterns,
            "vbscript": self.vbs_patterns,
            "batch": self.batch_patterns,
        }

        # For unknown types, check all patterns
        if script_type == "unknown":
            all_patterns = {}
            for patterns in pattern_map.values():
                all_patterns.update(patterns)
            return all_patterns

        return pattern_map.get(script_type, {})

    def _get_risk_level(self, risk_score: int) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        elif risk_score >= 20:
            return "low"
        return "minimal"

    def _generate_summary(self, script_type: str, behaviors: List[Dict],
                          mitre_techniques: List[Dict], risk_level: str) -> str:
        """Generate a human-readable summary of the analysis."""
        if not behaviors:
            return f"No suspicious behaviors detected in this {script_type} script."

        behavior_categories = list(set(b["category"] for b in behaviors))
        technique_names = list(set(t.get("name", "") for t in mitre_techniques if t.get("name")))

        summary_parts = [
            f"This {script_type} script exhibits {risk_level} risk behavior.",
            f"Detected {len(behaviors)} suspicious patterns across {len(behavior_categories)} categories.",
        ]

        if technique_names:
            summary_parts.append(
                f"Associated MITRE ATT&CK techniques: {', '.join(technique_names[:5])}."
            )

        # Add specific behavior highlights
        high_risk_behaviors = [b for b in behaviors if b.get("risk_contribution", 0) >= 80]
        if high_risk_behaviors:
            highlights = [b["description"] for b in high_risk_behaviors[:3]]
            summary_parts.append(f"Key concerns: {'; '.join(highlights)}.")

        return " ".join(summary_parts)

    def analyze_python(self, content: str) -> Dict:
        """Specialized analysis for Python scripts using AST."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return {"error": "Failed to parse Python script", "behaviors": []}

        behaviors = []
        imports = []
        dangerous_calls = []

        for node in ast.walk(tree):
            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)

            # Check function calls
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in ['eval', 'exec', 'compile', '__import__']:
                        dangerous_calls.append(func_name)
                elif isinstance(node.func, ast.Attribute):
                    attr_name = node.func.attr
                    if attr_name in ['system', 'popen', 'call', 'run', 'Popen']:
                        dangerous_calls.append(attr_name)

        # Analyze imports
        dangerous_imports = ['subprocess', 'os', 'socket', 'ctypes', 'winreg']
        risky_imports = [i for i in imports if any(d in i for d in dangerous_imports)]

        if risky_imports:
            behaviors.append({
                "category": "dangerous_imports",
                "description": f"Imports potentially dangerous modules: {', '.join(risky_imports)}",
                "risk_contribution": 50
            })

        if dangerous_calls:
            behaviors.append({
                "category": "dangerous_calls",
                "description": f"Uses dangerous functions: {', '.join(set(dangerous_calls))}",
                "risk_contribution": 70
            })

        return {
            "script_type": "python",
            "imports": imports,
            "dangerous_calls": dangerous_calls,
            "behaviors": behaviors
        }
