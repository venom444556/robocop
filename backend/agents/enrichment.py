"""Claude Enrichment Agent for orchestrating intelligence lookups and correlation."""

import logging
from typing import Dict, List, Optional, Any
import json
import asyncio

from .base import BaseAgent

logger = logging.getLogger(__name__)


class EnrichmentAgent(BaseAgent):
    """
    Claude-powered agent for orchestrating enrichment and correlating intelligence.
    """

    SYSTEM_PROMPT = """You are a threat intelligence analyst specializing in IOC enrichment and correlation.
Your role is to:

1. Prioritize which IOCs need enrichment based on their potential significance
2. Correlate enrichment data from multiple sources
3. Identify relationships between IOCs (infrastructure connections, campaigns, actors)
4. Summarize intelligence findings in actionable format
5. Identify gaps in intelligence and recommend additional lookups

Be thorough in correlation but efficient in your analysis. Focus on actionable intelligence
that helps defenders understand and respond to the threat."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize the Enrichment Agent.

        Args:
            api_key: Anthropic API key
            model: Claude model to use
        """
        super().__init__(api_key=api_key, model=model, system_prompt=self.SYSTEM_PROMPT)

    async def prioritize_iocs(self, iocs: List[Dict]) -> Dict:
        """
        Prioritize IOCs for enrichment based on potential significance.

        Args:
            iocs: List of extracted IOCs

        Returns:
            Dictionary with prioritized IOCs
        """
        prompt = f"""Analyze these IOCs and prioritize them for enrichment lookup.

## IOCs to Analyze:
```json
{json.dumps(iocs[:100], indent=2)}
```

Consider:
- IOC type (hashes are often more valuable than generic IPs)
- Context where found (command execution vs. comments)
- Uniqueness (common IPs vs. specific domains)
- Potential for attribution or campaign identification

Return a prioritized list in JSON format:
{{
  "high_priority": [
    {{"type": "...", "value": "...", "reason": "..."}}
  ],
  "medium_priority": [...],
  "low_priority": [...],
  "skip": [...]  // Common false positives or low-value IOCs
}}"""

        result = await self._call_claude(prompt, max_tokens=2048)

        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', result)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON from IOC prioritization response", exc_info=True)

        return {"prioritization": result}

    async def correlate_enrichment(self, enrichment_results: Dict) -> Dict:
        """
        Correlate enrichment data from multiple sources.

        Args:
            enrichment_results: Enrichment data keyed by IOC

        Returns:
            Dictionary with correlated intelligence
        """
        prompt = f"""Correlate this enrichment data from multiple intelligence sources.

## Enrichment Results:
```json
{json.dumps(enrichment_results, indent=2)}
```

Analyze for:
1. **Common Patterns**: IOCs that appear across multiple sources with similar verdicts
2. **Infrastructure Connections**: Related IPs, domains, or hosting providers
3. **Campaign Indicators**: Signs this is part of a larger campaign
4. **Actor Attribution**: Any indicators pointing to specific threat actors
5. **Timeline**: When these IOCs were first/last seen
6. **Confidence Assessment**: How reliable is the intelligence

Provide:
{{
  "correlation_summary": "...",
  "infrastructure_map": {{
    "clusters": [...],
    "connections": [...]
  }},
  "campaign_indicators": [...],
  "attribution": {{
    "suspected_actor": "...",
    "confidence": "...",
    "evidence": [...]
  }},
  "timeline": {{
    "first_seen": "...",
    "last_seen": "...",
    "activity_pattern": "..."
  }},
  "intelligence_gaps": [...],
  "recommended_actions": [...]
}}"""

        result = await self._call_claude(prompt)

        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', result)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON from enrichment correlation response", exc_info=True)

        return {"correlation": result}

    async def enrich_iocs(self, iocs: List[Dict]) -> Dict:
        """
        Orchestrate enrichment for a list of IOCs.
        All sources for a given IOC are queried in parallel via asyncio.gather().

        Args:
            iocs: List of IOCs to enrich

        Returns:
            Dictionary with all enrichment results
        """
        from enrichment import (
            VirusTotalClient, ShodanClient, URLhausClient,
            GoogleSafeBrowsingClient, IPQualityScoreClient,
            CheckPhishClient, UnshortenClient,
            GreyNoiseClient, AbuseIPDBClient, URLScanClient,
            AlienVaultOTXClient, MalwareBazaarClient,
            WhoisLookupClient, get_enrichment_cache,
        )

        vt = VirusTotalClient()
        shodan = ShodanClient()
        urlhaus = URLhausClient()
        gsb = GoogleSafeBrowsingClient()
        ipqs = IPQualityScoreClient()
        checkphish = CheckPhishClient()
        unshorten = UnshortenClient()
        greynoise = GreyNoiseClient()
        abuseipdb = AbuseIPDBClient()
        urlscan = URLScanClient()
        otx = AlienVaultOTXClient()
        malwarebazaar = MalwareBazaarClient()
        whois_client = WhoisLookupClient()
        cache = get_enrichment_cache()

        # Sources that require a "found" check in addition to no error
        FOUND_REQUIRED = {"urlhaus", "malwarebazaar"}

        async def _cached_enrich(coro, source: str, ioc_type: str, ioc_value: str):
            """Check cache, call API on miss, store successful results."""
            cached = cache.get(source, ioc_type, ioc_value)
            if cached is not None:
                return (source, cached)
            try:
                result = await coro
                if not result.get("error"):
                    cache.set(source, ioc_type, ioc_value, result)
                return (source, result)
            except Exception as e:
                return (source, {"error": f"Exception: {str(e)}"})

        def _collect(gathered, enrichment_list):
            """Filter gather results and append valid ones to enrichment list."""
            for source_name, result in gathered:
                if result.get("error"):
                    continue
                if source_name in FOUND_REQUIRED and not result.get("found"):
                    continue
                enrichment_list.append({"source": source_name, "data": result})

        results = {}

        for ioc in iocs[:50]:  # Limit to 50 IOCs
            ioc_type = ioc.get("type")
            ioc_value = ioc.get("value")

            if not ioc_value:
                continue

            results[ioc_value] = {"type": ioc_type, "enrichment": []}
            enrichment_list = results[ioc_value]["enrichment"]

            try:
                if ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
                    hash_type_arg = "sha256" if ioc_type == "hash_sha256" else "md5"
                    gathered = await asyncio.gather(
                        _cached_enrich(vt.lookup_hash(ioc_value), "virustotal", ioc_type, ioc_value),
                        _cached_enrich(urlhaus.lookup_hash(ioc_value, hash_type_arg), "urlhaus", ioc_type, ioc_value),
                        _cached_enrich(malwarebazaar.lookup_hash(ioc_value), "malwarebazaar", ioc_type, ioc_value),
                        _cached_enrich(otx.lookup_hash(ioc_value), "alienvault_otx", ioc_type, ioc_value),
                    )
                    _collect(gathered, enrichment_list)

                elif ioc_type == "ip":
                    gathered = await asyncio.gather(
                        _cached_enrich(vt.lookup_ip(ioc_value), "virustotal", ioc_type, ioc_value),
                        _cached_enrich(shodan.lookup_ip(ioc_value), "shodan", ioc_type, ioc_value),
                        _cached_enrich(ipqs.check_ip(ioc_value), "ipqualityscore", ioc_type, ioc_value),
                        _cached_enrich(greynoise.lookup_ip(ioc_value), "greynoise", ioc_type, ioc_value),
                        _cached_enrich(abuseipdb.check_ip(ioc_value), "abuseipdb", ioc_type, ioc_value),
                        _cached_enrich(otx.lookup_ip(ioc_value), "alienvault_otx", ioc_type, ioc_value),
                        _cached_enrich(whois_client.lookup_ip(ioc_value), "whois", ioc_type, ioc_value),
                    )
                    _collect(gathered, enrichment_list)

                elif ioc_type == "domain":
                    gathered = await asyncio.gather(
                        _cached_enrich(vt.lookup_domain(ioc_value), "virustotal", ioc_type, ioc_value),
                        _cached_enrich(urlhaus.lookup_host(ioc_value), "urlhaus", ioc_type, ioc_value),
                        _cached_enrich(otx.lookup_domain(ioc_value), "alienvault_otx", ioc_type, ioc_value),
                        _cached_enrich(urlscan.lookup_domain(ioc_value), "urlscan", ioc_type, ioc_value),
                        _cached_enrich(whois_client.lookup_domain(ioc_value), "whois", ioc_type, ioc_value),
                    )
                    _collect(gathered, enrichment_list)

                elif ioc_type == "url":
                    # Phase 1: expand shortened URL (sequential dependency)
                    lookup_url = ioc_value
                    if unshorten.is_shortened_url(ioc_value):
                        expand_result = await unshorten.expand(ioc_value)
                        if not expand_result.get("error") and expand_result.get("expanded_url"):
                            enrichment_list.append({"source": "url_unshorten", "data": expand_result})
                            lookup_url = expand_result["expanded_url"]

                    # Phase 2: all URL lookups in parallel
                    gathered = await asyncio.gather(
                        _cached_enrich(vt.lookup_url(lookup_url), "virustotal", ioc_type, ioc_value),
                        _cached_enrich(urlhaus.lookup_url(lookup_url), "urlhaus", ioc_type, ioc_value),
                        _cached_enrich(gsb.check_url(lookup_url), "google_safebrowsing", ioc_type, ioc_value),
                        _cached_enrich(ipqs.check_url(lookup_url), "ipqualityscore", ioc_type, ioc_value),
                        _cached_enrich(checkphish.scan_url(lookup_url), "checkphish", ioc_type, ioc_value),
                        _cached_enrich(urlscan.scan_url(lookup_url), "urlscan", ioc_type, ioc_value),
                        _cached_enrich(otx.lookup_url(lookup_url), "alienvault_otx", ioc_type, ioc_value),
                    )
                    _collect(gathered, enrichment_list)

                # Small delay between IOCs to respect rate limits
                await asyncio.sleep(0.5)

            except Exception as e:
                results[ioc_value]["error"] = str(e)

        # Enrich with NVD CVE data using accumulated results as context
        try:
            nvd_results = await self.enrich_with_nvd(results)
            if nvd_results and nvd_results.get("nvd_cves"):
                results["_nvd_enrichment"] = nvd_results
        except Exception as e:
            logger.warning("NVD enrichment failed: %s", str(e))

        return results

    async def summarize_intelligence(self, all_data: Dict) -> Dict:
        """
        Generate an intelligence summary from all enrichment data.

        Args:
            all_data: All enrichment and correlation data

        Returns:
            Dictionary with intelligence summary
        """
        prompt = f"""Generate a comprehensive threat intelligence summary from this data.

## All Intelligence Data:
```json
{json.dumps(all_data, indent=2)}
```

Provide an intelligence brief that includes:
1. **Threat Overview**: 2-3 sentence summary of the threat
2. **Key Findings**: Bullet points of most important discoveries
3. **IOC Reputation Summary**: Overall reputation of IOCs found
4. **Recommended Blocks**: IOCs that should be immediately blocked
5. **Monitoring Recommendations**: IOCs to monitor but not block
6. **Intelligence Confidence**: How confident are we in this intelligence
7. **Related Threats**: Any related campaigns or malware families
8. **Next Steps**: Recommended follow-up actions

Format as professional intelligence brief suitable for SOC leadership."""

        summary = await self._call_claude(prompt)

        return {
            "intelligence_summary": summary,
            "model_used": self.model
        }

    async def enrich_with_nvd(self, analysis_context: Dict) -> Dict:
        """
        Query NVD for relevant CVEs based on analysis context.
        Uses Claude to extract software/vulnerability keywords, then queries NVD API.

        Args:
            analysis_context: Analysis data to extract keywords from

        Returns:
            Dictionary with NVD CVE results
        """
        from enrichment import NVDClient

        # Step 1: Use Claude to extract relevant keywords for CVE search
        keyword_prompt = f"""From this malware analysis data, extract specific software names,
versions, vulnerability types, and exploit-related keywords that could be used to search
the National Vulnerability Database (NVD) for relevant CVEs.

Analysis data:
```json
{json.dumps(analysis_context, indent=2, default=str)[:6000]}
```

Return ONLY a JSON object:
{{"keywords": ["keyword1", "keyword2", "keyword3"]}}

Focus on: software names (e.g., "Apache Log4j"), protocol names exploited,
and specific vulnerability classes (e.g., "remote code execution").
Return at most 5 keywords. Only include keywords likely to find relevant CVEs."""

        keywords_result = await self._call_claude(keyword_prompt, max_tokens=512)

        # Parse keywords
        import re
        keywords = []
        try:
            json_match = re.search(r'\{[\s\S]*\}', keywords_result)
            if json_match:
                parsed = json.loads(json_match.group())
                keywords = parsed.get("keywords", [])[:5]
        except (json.JSONDecodeError, AttributeError):
            logger.warning("Failed to parse NVD keyword extraction response", exc_info=True)

        if not keywords:
            return {"nvd_cves": [], "keywords_searched": [], "note": "No relevant keywords extracted"}

        # Step 2: Query NVD for each keyword
        nvd = NVDClient()
        all_cves = []
        seen_ids = set()

        for keyword in keywords:
            try:
                result = await nvd.search_by_keyword(keyword, results_per_page=5)
                if not result.get("error"):
                    for cve in result.get("cves", []):
                        cve_id = cve.get("cve_id")
                        if cve_id and cve_id not in seen_ids:
                            seen_ids.add(cve_id)
                            cve["search_keyword"] = keyword
                            all_cves.append(cve)
            except Exception:
                logger.warning("NVD query failed for keyword '%s'", keyword, exc_info=True)
                continue

        return {
            "nvd_cves": all_cves,
            "keywords_searched": keywords,
            "total_cves_found": len(all_cves),
            "source": "nvd"
        }
