"""Claude Report Writer Agent for generating analysis reports."""

from typing import Dict, List, Optional, Any
import json
from datetime import datetime


class ReportWriterAgent:
    """
    Claude-powered agent for generating comprehensive analysis reports.
    """

    SYSTEM_PROMPT = """You are a technical writer specializing in malware analysis reports.
Your role is to create clear, professional, and actionable reports that communicate
complex technical findings to both technical and non-technical audiences.

Your reports should:
1. Start with an executive summary for leadership
2. Include detailed technical analysis for analysts
3. Provide clear, actionable recommendations
4. Use proper formatting and structure
5. Include all relevant IOCs in a usable format
6. Be concise but comprehensive

Write in a professional, objective tone. Avoid speculation and clearly indicate
confidence levels for any assessments."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize the Report Writer Agent.

        Args:
            api_key: Anthropic API key
            model: Claude model to use
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model or settings.claude_model

    async def _call_claude(self, prompt: str, max_tokens: int = 8192) -> str:
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

    async def generate_narrative(self, submission: Any, analysis_results: List[Dict],
                                 iocs: List[Dict], enrichment_data: Dict) -> str:
        """
        Generate narrative analysis for the report.

        Args:
            submission: Submission object
            analysis_results: List of analysis results
            iocs: List of IOCs
            enrichment_data: Enrichment data

        Returns:
            Narrative text for the report
        """
        submission_info = {
            "id": submission.id,
            "type": submission.type.value if hasattr(submission.type, 'value') else str(submission.type),
            "filename": submission.filename,
            "url": submission.original_url,
            "hash": submission.file_hash_sha256,
            "submitted_at": submission.created_at.isoformat() if submission.created_at else None
        }

        prompt = f"""Generate a comprehensive narrative analysis for this malware analysis report.

## Submission Information:
```json
{json.dumps(submission_info, indent=2)}
```

## Analysis Results:
```json
{json.dumps(analysis_results[:10], indent=2)}
```

## Extracted IOCs ({len(iocs)} total):
```json
{json.dumps(iocs[:30], indent=2)}
```

## Enrichment Data:
```json
{json.dumps(dict(list(enrichment_data.items())[:20]), indent=2)}
```

Generate a professional report narrative that includes:

1. **Executive Summary** (2-3 paragraphs)
   - What was analyzed
   - Key findings
   - Overall threat assessment
   - Recommended actions

2. **Technical Analysis**
   - Detailed breakdown of behaviors observed
   - Code analysis findings (if applicable)
   - Network activity analysis
   - Persistence mechanisms identified

3. **Threat Intelligence**
   - IOC analysis and reputation
   - Related campaigns or malware families
   - Threat actor attribution (if applicable)
   - Historical context

4. **MITRE ATT&CK Mapping**
   - List all identified techniques with IDs
   - Explain how each technique was used

5. **Recommendations**
   - Immediate actions
   - Detection rules to implement
   - Long-term security improvements

Write in markdown format with proper headers and formatting."""

        narrative = await self._call_claude(prompt)
        return narrative

    async def generate_executive_summary(self, all_data: Dict) -> str:
        """
        Generate an executive summary for leadership.

        Args:
            all_data: All analysis data

        Returns:
            Executive summary text
        """
        prompt = f"""Generate a concise executive summary (max 300 words) for security leadership.

## Analysis Data:
```json
{json.dumps(all_data, indent=2)}
```

The summary should:
1. State what was analyzed (1 sentence)
2. Summarize the threat level and key findings (2-3 sentences)
3. Highlight business impact potential (1-2 sentences)
4. Provide top 3 recommended actions (bullet points)
5. Include overall risk rating (Critical/High/Medium/Low)

Write for a non-technical audience while maintaining accuracy.
Use clear, direct language and avoid jargon."""

        summary = await self._call_claude(prompt, max_tokens=1024)
        return summary

    async def generate_ioc_table(self, iocs: List[Dict], enrichment_data: Dict) -> str:
        """
        Generate formatted IOC tables for the report.

        Args:
            iocs: List of IOCs
            enrichment_data: Enrichment data for IOCs

        Returns:
            Formatted IOC tables in markdown
        """
        # Group IOCs by type
        iocs_by_type = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in iocs_by_type:
                iocs_by_type[ioc_type] = []
            iocs_by_type[ioc_type].append(ioc)

        tables = []

        for ioc_type, type_iocs in iocs_by_type.items():
            table = f"\n### {ioc_type.upper().replace('_', ' ')} Indicators\n\n"
            table += "| Value | Context | Reputation |\n"
            table += "|-------|---------|------------|\n"

            for ioc in type_iocs[:25]:  # Limit to 25 per type
                value = ioc.get("value", "")
                context = ioc.get("context", "-")[:50]

                # Get reputation from enrichment
                reputation = "Unknown"
                if value in enrichment_data:
                    enrichments = enrichment_data[value].get("enrichment", [])
                    for e in enrichments:
                        if e.get("source") == "virustotal":
                            detections = e.get("data", {}).get("total_detections", 0)
                            if detections > 10:
                                reputation = f"Malicious ({detections} detections)"
                            elif detections > 0:
                                reputation = f"Suspicious ({detections} detections)"
                            else:
                                reputation = "Clean"
                            break

                # Escape pipe characters in values
                value = value.replace("|", "\\|")
                context = context.replace("|", "\\|")

                table += f"| `{value}` | {context} | {reputation} |\n"

            tables.append(table)

        return "\n".join(tables)

    async def generate_detection_rules(self, analysis_data: Dict) -> str:
        """
        Generate detection rules (YARA, Sigma) based on analysis.

        Args:
            analysis_data: Analysis data

        Returns:
            Detection rules in markdown
        """
        prompt = f"""Generate detection rules based on this malware analysis.

## Analysis Data:
```json
{json.dumps(analysis_data, indent=2)}
```

Generate:
1. **YARA Rule** - For file-based detection
2. **Sigma Rule** - For log-based detection

Rules should:
- Be production-ready with proper metadata
- Include meaningful descriptions
- Focus on unique indicators (avoid generic patterns)
- Include proper escaping and syntax

Format as code blocks with proper syntax highlighting."""

        rules = await self._call_claude(prompt, max_tokens=2048)
        return rules

    async def generate_full_report(self, submission: Any, analysis_results: List[Dict],
                                   iocs: List[Dict], enrichment_data: Dict,
                                   reasoning_analysis: Dict) -> Dict:
        """
        Generate a complete analysis report.

        Args:
            submission: Submission object
            analysis_results: List of analysis results
            iocs: List of IOCs
            enrichment_data: Enrichment data
            reasoning_analysis: Reasoning agent analysis

        Returns:
            Dictionary with full report content
        """
        # Generate all sections
        narrative = await self.generate_narrative(
            submission, analysis_results, iocs, enrichment_data
        )

        executive_summary = await self.generate_executive_summary({
            "submission_type": submission.type.value if hasattr(submission.type, 'value') else str(submission.type),
            "analysis_results": analysis_results[:5],
            "ioc_count": len(iocs),
            "reasoning": reasoning_analysis
        })

        ioc_tables = await self.generate_ioc_table(iocs, enrichment_data)

        detection_rules = await self.generate_detection_rules({
            "analysis": analysis_results,
            "iocs": iocs[:20]
        })

        # Compile full report
        report = f"""# Malware Analysis Report

**Report ID:** {submission.id}
**Generated:** {datetime.utcnow().isoformat()}
**Submission Type:** {submission.type.value if hasattr(submission.type, 'value') else str(submission.type)}

---

## Executive Summary

{executive_summary}

---

{narrative}

---

## Indicators of Compromise

{ioc_tables}

---

## Detection Rules

{detection_rules}

---

## Appendix

### Analysis Metadata
- **Submission ID:** {submission.id}
- **Filename:** {submission.filename or 'N/A'}
- **URL:** {submission.original_url or 'N/A'}
- **SHA256:** {submission.file_hash_sha256 or 'N/A'}
- **Analysis Date:** {datetime.utcnow().isoformat()}
- **Total IOCs:** {len(iocs)}

---

*Report generated by Malware Analysis Platform*
"""

        return {
            "full_report": report,
            "executive_summary": executive_summary,
            "narrative": narrative,
            "ioc_tables": ioc_tables,
            "detection_rules": detection_rules,
            "model_used": self.model
        }
