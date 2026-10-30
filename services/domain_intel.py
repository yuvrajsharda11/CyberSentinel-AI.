"""Opt-in domain reputation lookup using public RDAP and VirusTotal APIs."""
import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import quote


def lookup_domain(domain):
    domain = (domain or "").strip().lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        return {"error": "Enter a valid public domain name."}
    result = {"domain": domain, "sources": [], "note": "The domain is shared with the selected public lookup services."}
    req = urllib.request.Request("https://rdap.org/domain/" + quote(domain), headers={"User-Agent": "CyberSentinel-Educational/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read(500_000))
        events = data.get("events", [])
        created = next((e.get("eventDate") for e in events if e.get("eventAction") == "registration"), None)
        result["registration_date"] = created
        registrar = "Not listed"
        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                registrar_row = next((field for field in vcard[1] if field and field[0] == "fn" and len(field) > 3), None)
                if registrar_row:
                    registrar = registrar_row[3]
                    break
        result["registrar"] = registrar
        result["sources"].append("Public RDAP")
    except Exception as exc:
        result["rdap_status"] = "Lookup unavailable: " + type(exc).__name__
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if api_key:
        request = urllib.request.Request("https://www.virustotal.com/api/v3/domains/" + quote(domain), headers={"x-apikey": api_key})
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                vt = json.loads(response.read(500_000)).get("data", {}).get("attributes", {})
            stats = vt.get("last_analysis_stats", {})
            result["virustotal_stats"] = stats
            result["virustotal_reputation"] = vt.get("reputation")
            result["sources"].append("VirusTotal")
        except Exception as exc:
            result["virustotal_status"] = "Lookup unavailable: " + type(exc).__name__
    else:
        result["virustotal_status"] = "Set VIRUSTOTAL_API_KEY to enable VirusTotal reputation."
    return result


def lookup_file_hash(file_hash):
    """Opt-in VirusTotal lookup; sharing a hash can reveal that a file is under investigation."""
    value = (file_hash or "").strip().lower()
    if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
        return {"error": "Enter a valid MD5, SHA-1, or SHA-256 hash."}
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VirusTotal lookup is unavailable because VIRUSTOTAL_API_KEY is not configured."}
    request = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + quote(value), headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            data = json.loads(response.read(500_000)).get("data", {}).get("attributes", {})
        return {"hash": value, "sources": ["VirusTotal"],
                "last_analysis_stats": data.get("last_analysis_stats", {}),
                "reputation": data.get("reputation"),
                "meaningful_limit": "A hash lookup shares the hash with VirusTotal and only returns its existing record; it does not upload the file."}
    except Exception as exc:
        return {"hash": value, "status": "Lookup unavailable: " + type(exc).__name__}
