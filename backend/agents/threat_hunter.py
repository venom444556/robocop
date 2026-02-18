"""Claude Threat Hunt Agent for evidence-grounded threat analysis."""

import logging
from typing import Dict, List, Optional, Any
import json
import re

from .base import BaseAgent

logger = logging.getLogger(__name__)


class ThreatHuntAgent(BaseAgent):
    """
    Claude-powered agent for specialized threat hunting with evidence-grounded findings.
    Inspired by Autonomous SOC Analyst's context-specific analysis prompts.
    """

    SYSTEM_PROMPTS = {
        "file": """You are a threat hunter specializing in file-based malware analysis.
Your expertise covers:
- Static analysis of scripts (PowerShell, JavaScript, VBScript, Python, Batch)
- Binary behavior patterns and obfuscation techniques
- Identifying malware families from code patterns
- LOLBin (Living Off the Land Binary) abuse detection
- Multi-stage payload identification

When analyzing, you MUST:
- Ground every finding in concrete evidence from the data provided
- Assign severity and confidence levels with explicit reasoning
- Reference specific IOCs, code patterns, or behaviors as evidence
- Recommend specific response actions for each finding""",

        "url": """You are a threat hunter specializing in web-based threats.
Your expertise covers:
- Phishing infrastructure identification
- Drive-by download detection
- Malicious redirect chain analysis
- Domain reputation and infrastructure correlation
- Web-based C2 communication patterns

When analyzing, you MUST:
- Ground every finding in concrete evidence from the data provided
- Assign severity and confidence levels with explicit reasoning
- Reference specific URLs, domains, or network patterns as evidence
- Recommend specific response actions for each finding""",

        "sandbox_report": """You are a threat hunter specializing in behavioral analysis of malware execution.
Your expertise covers:
- Process execution chain analysis (parent-child relationships)
- Registry persistence mechanism detection
- Network beaconing and C2 communication patterns
- File system artifact analysis
- Defense evasion and anti-analysis technique identification
- Lateral movement indicator detection

When analyzing, you MUST:
- Ground every finding in concrete evidence from the data provided
- Assign severity and confidence levels with explicit reasoning
- Reference specific processes, network connections, or file operations as evidence
- Recommend specific response actions for each finding""",

        "default": """You are a senior SOC threat hunter with deep expertise across all domains
of security analysis. You analyze malware samples, network traffic, and system behaviors
to identify threats with precision.

When analyzing, you MUST:
- Ground every finding in concrete evidence from the data provided
- Assign severity and confidence levels with explicit reasoning
- Reference specific indicators or behaviors as evidence
- Recommend specific response actions for each finding"""
    }

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """Initialize the Threat Hunt Agent."""
        super().__init__(
            api_key=api_key,
            model=model,
            system_prompt=self.SYSTEM_PROMPTS["default"],
        )

    def _get_system_prompt(self, submission_type: str) -> str:
        """Select the appropriate system prompt for the submission type."""
        return self.SYSTEM_PROMPTS.get(submission_type, self.SYSTEM_PROMPTS["default"])

    async def hunt(self, submission_type: str, analysis_data: Dict,
                   iocs: List[Dict], enrichment_data: Dict) -> Dict:
        """
        Execute threat hunt analysis with evidence-grounded findings.

        Args:
            submission_type: Type of submission (file, url, sandbox_report)
            analysis_data: Results from analyzers
            iocs: Extracted IOCs
            enrichment_data: Intelligence enrichment data

        Returns:
            Dictionary with threat hunt findings
        """
        system_prompt = self._get_system_prompt(submission_type)

        prompt = f"""Conduct a thorough threat hunt analysis on the following data.
Every finding MUST be grounded in concrete evidence from the data provided.
Do NOT include speculative findings without supporting evidence.

## Analysis Data:
```json
{json.dumps(analysis_data, indent=2, default=str)[:8000]}
```

## IOCs ({len(iocs)} total):
```json
{json.dumps(iocs[:30], indent=2)}
```

## Enrichment Data:
```json
{json.dumps(enrichment_data, indent=2, default=str)[:4000]}
```

For each finding, you MUST provide:
1. A unique finding ID (F-001, F-002, etc.)
2. Severity: Critical / High / Medium / Low / Informational
3. Confidence: High / Medium / Low — with explicit reasoning
4. Concrete evidence (specific IOC values, code patterns, behavior indicators)
5. Recommended action: investigate / contain / monitor / dismiss

Return a JSON response with this exact structure:
{{
  "findings": [
    {{
      "id": "F-001",
      "title": "Finding title",
      "description": "Detailed description",
      "severity": "High",
      "confidence": "High",
      "confidence_reasoning": "Why this confidence level",
      "evidence": [
        {{
          "type": "ioc|behavior|code_pattern|enrichment",
          "value": "Specific indicator or pattern",
          "source": "Where this was found"
        }}
      ],
      "recommendation": "investigate",
      "recommendation_detail": "Specific steps to take",
      "mitre_techniques": ["T1059.001"]
    }}
  ],
  "hunt_summary": "Overall threat assessment summary"
}}"""

        result = await self._call_claude(prompt, system_prompt=system_prompt)

        # Parse JSON from response
        try:
            json_match = re.search(r'\{[\s\S]*\}', result)
            if json_match:
                parsed = json.loads(json_match.group())
                return {
                    "threat_hunt": parsed,
                    "submission_type": submission_type,
                    "model_used": self.model
                }
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON from threat hunt response", exc_info=True)

        return {
            "threat_hunt": {"raw_response": result},
            "submission_type": submission_type,
            "model_used": self.model
        }
