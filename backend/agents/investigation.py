"""Claude DFIR Investigation Agent for generating actionable response plans."""

from typing import Dict, List, Optional, Any
import json
import re


class InvestigationAgent:
    """
    Claude-powered agent for generating DFIR investigation and incident response plans.
    Inspired by Multi-Agent SOC Analyst investigation workflows.
    """

    SYSTEM_PROMPT = """You are a senior DFIR (Digital Forensics and Incident Response) analyst
with extensive experience in malware incident response, threat hunting, and forensic investigation.

Your role is to generate actionable investigation and response plans based on malware analysis findings.

Your investigation plans must include:
1. Structured investigation steps with clear priorities (P1=immediate, P2=urgent/24h, P3=standard/72h, P4=low)
2. Containment actions ordered by urgency with scope (host, network, domain)
3. Eradication procedures to remove the threat
4. Recovery steps to restore normal operations
5. Evidence preservation guidance
6. Required tools and resources

Be specific and actionable. Reference concrete IOCs, MITRE techniques, and behaviors from the analysis.
Every recommendation must be grounded in the evidence provided — do not speculate beyond the data.
Format all output as valid JSON."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """Initialize the Investigation Agent."""
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

    async def generate_investigation_plan(self, analysis_data: Dict,
                                           iocs: List[Dict],
                                           mitre_techniques: List[Dict],
                                           enrichment_data: Dict) -> Dict:
        """
        Generate a comprehensive DFIR investigation plan.

        Args:
            analysis_data: Results from static/dynamic analysis
            iocs: List of extracted IOCs
            mitre_techniques: MITRE ATT&CK techniques (validated)
            enrichment_data: Enrichment data from intelligence sources

        Returns:
            Dictionary with structured investigation plan
        """
        prompt = f"""Based on the following malware analysis, generate a detailed DFIR investigation
and incident response plan.

## Analysis Results:
```json
{json.dumps(analysis_data, indent=2, default=str)[:8000]}
```

## IOCs ({len(iocs)} total):
```json
{json.dumps(iocs[:30], indent=2)}
```

## MITRE ATT&CK Techniques:
```json
{json.dumps(mitre_techniques[:20], indent=2)}
```

## Enrichment Data:
```json
{json.dumps(enrichment_data, indent=2, default=str)[:4000]}
```

Provide a structured JSON response with this exact schema:
{{
  "investigation_steps": [
    {{
      "step": 1,
      "priority": "P1",
      "action": "Specific investigation action",
      "rationale": "Why this step is needed",
      "iocs_involved": ["ioc1", "ioc2"],
      "tools": ["tool1"]
    }}
  ],
  "containment_actions": [
    {{
      "priority": "P1",
      "action": "Specific containment action",
      "scope": "host|network|domain",
      "risk": "Risk of this action",
      "dependencies": []
    }}
  ],
  "eradication_procedures": [
    {{
      "step": 1,
      "action": "Eradication step",
      "verification": "How to verify completion"
    }}
  ],
  "recovery_steps": [
    {{
      "step": 1,
      "action": "Recovery action",
      "prerequisites": []
    }}
  ],
  "evidence_preservation": [
    "Evidence item to preserve"
  ],
  "analyst_notes": "Key observations and caveats",
  "required_tools": ["tool1", "tool2"]
}}"""

        result = await self._call_claude(prompt)

        # Parse JSON from response
        try:
            json_match = re.search(r'\{[\s\S]*\}', result)
            if json_match:
                parsed = json.loads(json_match.group())
                return {
                    "investigation_plan": parsed,
                    "model_used": self.model
                }
        except json.JSONDecodeError:
            pass

        return {
            "investigation_plan": {"raw_response": result},
            "model_used": self.model
        }

    async def generate_containment_priorities(self, threat_data: Dict) -> Dict:
        """
        Generate quick containment priority list for urgent response.

        Args:
            threat_data: Combined threat analysis data

        Returns:
            Dictionary with prioritized containment actions
        """
        prompt = f"""Based on this threat data, provide an immediate containment priority list.
Focus only on the most urgent actions needed right now.

## Threat Data:
```json
{json.dumps(threat_data, indent=2, default=str)[:6000]}
```

Return JSON:
{{
  "immediate_actions": [
    {{
      "action": "What to do right now",
      "scope": "host|network|domain",
      "urgency": "critical|high|medium"
    }}
  ],
  "block_list": [
    {{
      "type": "ip|domain|hash",
      "value": "indicator value",
      "where": "firewall|proxy|edr|dns"
    }}
  ]
}}"""

        result = await self._call_claude(prompt, max_tokens=2048)

        try:
            json_match = re.search(r'\{[\s\S]*\}', result)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

        return {"containment_priorities": result, "model_used": self.model}
