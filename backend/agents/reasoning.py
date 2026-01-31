"""Claude Reasoning Agent for malware analysis and MITRE ATT&CK mapping."""

from typing import Dict, List, Optional, Any
import json


class ReasoningAgent:
    """
    Claude-powered agent for analyzing malware behaviors and mapping to MITRE ATT&CK.
    """

    SYSTEM_PROMPT = """You are an expert malware analyst and threat intelligence specialist.
Your role is to analyze malware samples, scripts, and indicators of compromise (IOCs) to:

1. Identify malicious behaviors and techniques
2. Map behaviors to MITRE ATT&CK framework techniques
3. Assess threat severity and potential impact
4. Identify malware family characteristics when possible
5. Provide actionable intelligence for defenders

When analyzing, be thorough but concise. Focus on:
- What the malware/script is trying to accomplish
- Specific techniques used (with ATT&CK IDs when applicable)
- Indicators that can be used for detection
- Recommended mitigations

Always structure your analysis in a clear, professional format suitable for a security operations team."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize the Reasoning Agent.

        Args:
            api_key: Anthropic API key
            model: Claude model to use
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model or settings.claude_model

    async def _call_claude(self, prompt: str, max_tokens: int = 4096) -> str:
        """Make a call to Claude API."""
        import anthropic

        if not self.api_key:
            return "Error: Anthropic API key not configured"

        try:
            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            message = await client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            return message.content[0].text
        except Exception as e:
            return f"Error calling Claude API: {str(e)}"

    async def analyze_script(self, script_content: str, script_type: str,
                            analysis_results: Dict) -> Dict:
        """
        Analyze a script for malicious behaviors.

        Args:
            script_content: The script content
            script_type: Type of script (powershell, javascript, etc.)
            analysis_results: Results from static analysis

        Returns:
            Dictionary with reasoning analysis
        """
        # Truncate script if too long
        max_script_length = 10000
        truncated = len(script_content) > max_script_length
        script_sample = script_content[:max_script_length]

        prompt = f"""Analyze this {script_type} script for malicious behaviors.

## Script Content {"(truncated)" if truncated else ""}:
```{script_type}
{script_sample}
```

## Static Analysis Results:
```json
{json.dumps(analysis_results, indent=2)}
```

Please provide:
1. **Executive Summary**: Brief overview of what this script does (2-3 sentences)
2. **Malicious Behaviors**: List each malicious behavior identified
3. **MITRE ATT&CK Mapping**: Map behaviors to specific ATT&CK techniques with IDs
4. **Threat Assessment**: Rate severity (Critical/High/Medium/Low) with justification
5. **Malware Family**: If recognizable patterns exist, identify potential family
6. **Detection Opportunities**: Specific strings, patterns, or behaviors for detection rules
7. **Recommended Mitigations**: Actionable steps to prevent/detect this threat

Format your response as structured markdown."""

        analysis = await self._call_claude(prompt)

        return {
            "reasoning_analysis": analysis,
            "script_type": script_type,
            "truncated": truncated,
            "model_used": self.model
        }

    async def analyze_iocs(self, iocs: List[Dict], enrichment_data: Dict) -> Dict:
        """
        Analyze IOCs and enrichment data for threat context.

        Args:
            iocs: List of extracted IOCs
            enrichment_data: Enrichment data from various sources

        Returns:
            Dictionary with IOC analysis
        """
        prompt = f"""Analyze these Indicators of Compromise (IOCs) and their enrichment data.

## Extracted IOCs:
```json
{json.dumps(iocs[:50], indent=2)}
```

## Enrichment Data:
```json
{json.dumps(enrichment_data, indent=2)}
```

Please provide:
1. **IOC Summary**: Overview of the IOCs found and their significance
2. **Threat Attribution**: Any indicators of threat actor or campaign
3. **Infrastructure Analysis**: Analysis of network infrastructure (IPs, domains)
4. **Malware Correlation**: Connections to known malware families
5. **Risk Assessment**: Overall risk level based on IOC reputation
6. **Hunting Recommendations**: Additional IOCs or patterns to hunt for
7. **Blocking Recommendations**: Which IOCs should be immediately blocked

Format your response as structured markdown."""

        analysis = await self._call_claude(prompt)

        return {
            "ioc_analysis": analysis,
            "ioc_count": len(iocs),
            "model_used": self.model
        }

    async def analyze_sandbox_report(self, sandbox_data: Dict) -> Dict:
        """
        Analyze parsed sandbox report data.

        Args:
            sandbox_data: Parsed sandbox report

        Returns:
            Dictionary with sandbox analysis
        """
        prompt = f"""Analyze this sandbox analysis report for a malware sample.

## Sandbox Report:
```json
{json.dumps(sandbox_data, indent=2)}
```

Please provide:
1. **Executive Summary**: What the sample does and its purpose
2. **Execution Flow**: Step-by-step breakdown of malware execution
3. **Persistence Mechanisms**: How the malware maintains persistence
4. **Network Activity**: Analysis of C2 communication and data exfiltration
5. **Evasion Techniques**: Anti-analysis or defense evasion methods
6. **MITRE ATT&CK Mapping**: Complete mapping of observed techniques
7. **Malware Classification**: Family identification and confidence level
8. **Detection Signatures**: YARA rules or Sigma rules for detection
9. **Incident Response**: Recommended IR steps if this is found in environment

Format your response as structured markdown."""

        analysis = await self._call_claude(prompt)

        return {
            "sandbox_analysis": analysis,
            "source": sandbox_data.get("source", "unknown"),
            "model_used": self.model
        }

    async def map_to_attack(self, behaviors: List[Dict]) -> Dict:
        """
        Map observed behaviors to MITRE ATT&CK techniques.

        Args:
            behaviors: List of observed behaviors

        Returns:
            Dictionary with ATT&CK mapping
        """
        prompt = f"""Map these observed malware behaviors to MITRE ATT&CK techniques.

## Observed Behaviors:
```json
{json.dumps(behaviors, indent=2)}
```

For each behavior, provide:
1. ATT&CK Technique ID (e.g., T1059.001)
2. Technique Name
3. Tactic
4. Confidence Level (High/Medium/Low)
5. Supporting Evidence

Also provide:
- Attack chain visualization (which techniques lead to others)
- Recommended detection rules for each technique
- Relevant sub-techniques if applicable

Format your response as structured JSON with the following schema:
{{
  "techniques": [
    {{
      "id": "T1059.001",
      "name": "PowerShell",
      "tactic": "Execution",
      "confidence": "High",
      "evidence": "Script uses Invoke-Expression with encoded commands",
      "detection": "Monitor for powershell.exe spawning with -enc flag"
    }}
  ],
  "attack_chain": "T1566 -> T1204 -> T1059.001 -> T1105 -> ...",
  "summary": "..."
}}"""

        analysis = await self._call_claude(prompt)

        # Try to parse as JSON
        try:
            # Find JSON block in response
            import re
            json_match = re.search(r'\{[\s\S]*\}', analysis)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

        return {
            "attack_mapping": analysis,
            "model_used": self.model
        }

    async def assess_threat_severity(self, all_analysis: Dict) -> Dict:
        """
        Provide overall threat severity assessment.

        Args:
            all_analysis: Combined analysis from all sources

        Returns:
            Dictionary with severity assessment
        """
        prompt = f"""Based on all the analysis data, provide an overall threat severity assessment.

## Combined Analysis:
```json
{json.dumps(all_analysis, indent=2)}
```

Provide:
1. **Overall Severity**: Critical / High / Medium / Low
2. **Confidence Level**: How confident are you in this assessment (0-100%)
3. **Justification**: Key factors that determined the severity
4. **Potential Impact**: What damage could this threat cause
5. **Urgency**: How quickly should this be addressed
6. **Recommended Priority**: P1 (immediate) / P2 (urgent) / P3 (standard) / P4 (low)

Format as JSON:
{{
  "severity": "High",
  "confidence": 85,
  "justification": "...",
  "potential_impact": ["data theft", "lateral movement", "..."],
  "urgency": "Address within 24 hours",
  "priority": "P2",
  "summary": "..."
}}"""

        analysis = await self._call_claude(prompt, max_tokens=1024)

        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', analysis)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

        return {
            "severity_assessment": analysis,
            "model_used": self.model
        }
