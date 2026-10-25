import hashlib
import ipaddress
import json
import re
import socket
import ssl
import tempfile
import os
from datetime import date, datetime
from html import unescape
from urllib.parse import quote, urlparse

import requests
import dns.resolver
import whois
import phonenumbers
from phonenumbers import carrier, geocoder
from ddgs import DDGS

import config

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": config.USER_AGENT,
    "Accept": "text/html,application/json,text/plain,*/*",
})


def result(source, status, summary, details=None, url=""):
    return {
        "source": source,
        "status": status,
        "summary": summary,
        "details": details if details is not None else {},
        "url": url,
        "retrieved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def request_json(source, url, method="GET", **kwargs):
    try:
        response = SESSION.request(method, url, timeout=config.REQUEST_TIMEOUT, **kwargs)
        if response.status_code >= 400:
            return result(source, "unavailable", f"HTTP {response.status_code}",
                          {"http_status": response.status_code}, url)
        try:
            data = response.json()
        except ValueError:
            data = {"response": response.text[:2000]}
        return result(source, "success", "Response received", data, url)
    except requests.RequestException as exc:
        return result(source, "error", f"Request failed: {exc}", url=url)


def serialize(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (list, tuple, set)):
        return [serialize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): serialize(item) for key, item in value.items()}
    return str(value) if value is not None else None


def whois_lookup(domain):
    try:
        data = whois.whois(domain)
        fields = ("domain_name", "registrar", "creation_date", "expiration_date",
                  "updated_date", "name_servers", "status", "emails", "org", "country")
        details = {key: serialize(getattr(data, key, None))
                   for key in fields if getattr(data, key, None)}
        return result("WHOIS", "success" if details else "no_data",
                      "Registration data retrieved" if details else "No registration data found",
                      details, f"https://lookup.icann.org/en/lookup?name={quote(domain)}")
    except Exception as exc:
        return result("WHOIS", "unavailable", f"WHOIS lookup failed: {exc}")


def dns_lookup(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    records, errors = {}, {}
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA", "SRV", "DNSKEY", "DS"):
        try:
            records[record_type] = [str(item) for item in resolver.resolve(domain, record_type)]
        except Exception as exc:
            errors[record_type] = str(exc)
    return result("DNS", "success" if records else "no_data", "DNS queries completed",
                  {"domain": domain, "records": records, "errors": errors},
                  f"https://dns.google/query?name={quote(domain)}")


def email_security_lookup(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    records, errors = {}, {}
    for name, record_type in ((domain, "TXT"), ("_dmarc." + domain, "TXT"),
                              (domain, "DNSKEY"), (domain, "DS"), (domain, "CAA")):
        key = f"{name}:{record_type}"
        try:
            values = [str(item) for item in resolver.resolve(name, record_type)]
            if record_type == "TXT":
                values = [value.replace('" "', "").replace('"', "") for value in values]
            records[key] = values
        except Exception as exc:
            errors[key] = str(exc)
    txt = records.get(f"{domain}:TXT", [])
    dmarc_txt = records.get(f"_dmarc.{domain}:TXT", [])
    details = {
        "domain": domain,
        "spf_records": [v for v in txt if v.lower().startswith("v=spf1")],
        "dmarc_records": [v for v in dmarc_txt if v.lower().startswith("v=dmarc1")],
        "dnskey_records": records.get(f"{domain}:DNSKEY", []),
        "ds_records": records.get(f"{domain}:DS", []),
        "caa_records": records.get(f"{domain}:CAA", []),
        "all_records": records,
        "lookup_errors": errors,
        "note": "DNS lookup failures do not prove that a security control is absent. DNSSEC requires validation of the chain of trust.",
    }
    return result("Email & DNS Security", "success" if records else "no_data",
                  "Checked SPF, DMARC, DNSKEY/DS and CAA records", details,
                  f"https://dns.google/query?name={quote(domain)}")


def tls_lookup(domain, port=443):
    cert_path = None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=config.REQUEST_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                version = tls.version()
        details = {
            "hostname": domain, "port": port, "tls_version": version,
            "cipher": cipher[0] if cipher else None,
            "certificate_sha256": hashlib.sha256(der).hexdigest(),
            "certificate_size": len(der),
            "note": "The certificate was retrieved without validating its trust chain; this is not a safety verdict.",
        }
        try:
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", suffix=".pem", delete=False) as file:
                file.write(pem)
                cert_path = file.name
            decoded = ssl._ssl._test_decode_cert(cert_path)
            for key in ("subject", "issuer", "version", "serialNumber", "notBefore", "notAfter", "subjectAltName"):
                if decoded.get(key):
                    details[key] = serialize(decoded[key])
            details["dns_names"] = [name for kind, name in decoded.get("subjectAltName", []) if kind == "DNS"][:100]
        except Exception as exc:
            details["certificate_parse_note"] = str(exc)[:300]
        finally:
            if cert_path and os.path.exists(cert_path):
                try:
                    os.unlink(cert_path)
                except OSError:
                    pass
        return result("TLS Certificate", "success", "Retrieved server TLS certificate", details, f"https://{domain}/")
    except Exception as exc:
        return result("TLS Certificate", "unavailable", f"Could not retrieve certificate: {exc}",
                      {"hostname": domain, "port": port}, f"https://{domain}/")


def certificate_transparency_lookup(domain, limit=100):
    response = request_json("Certificate Transparency", "https://crt.sh/",
                            params={"q": "%." + domain, "output": "json"})
    if response.get("status") != "success":
        return response
    raw = response.get("details", [])
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = []
    if not isinstance(raw, list):
        raw = []
    certificates, subdomains, seen = [], set(), set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        fingerprint = str(item.get("SHA-256") or item.get("sha256") or "")
        cert_id = str(item.get("id") or "")
        unique_key = fingerprint or cert_id
        if unique_key and unique_key in seen:
            continue
        if unique_key:
            seen.add(unique_key)
        names = str(item.get("name_value") or item.get("common_name") or "")
        for name in names.splitlines():
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if (name == domain or name.endswith("." + domain)) and "*" not in name and " " not in name:
                subdomains.add(name)
        certificates.append({
            "id": item.get("id"), "issuer": item.get("issuer_name"),
            "common_name": item.get("common_name"), "names": names,
            "not_before": item.get("not_before"), "not_after": item.get("not_after"),
            "serial_number": item.get("serial_number"), "fingerprint": fingerprint,
        })
        if len(certificates) >= limit:
            break
    return result("Certificate Transparency", "success" if certificates else "no_data",
                  f"Found {len(certificates)} certificates and {len(subdomains)} names",
                  {"domain": domain, "subdomains": sorted(subdomains), "certificates": certificates,
                   "certificate_count": len(certificates), "subdomain_count": len(subdomains),
                   "note": "A public certificate record does not prove that a host is currently online or that all names share an owner."},
                  "https://crt.sh/?q=%25." + quote(domain))


def urlhaus_host_lookup(host):
    return request_json("URLhaus", "https://urlhaus-api.abuse.ch/v1/host/",
                        method="POST", data={"host": host})


def domain_lookup(value, kind="domain"):
    domain = (urlparse(value).hostname or "") if kind == "url" else str(value).strip()
    domain = domain.lower().rstrip(".")
    if not domain or "/" in domain or " " in domain or not re.fullmatch(r"[a-zA-Z0-9._-]+", domain):
        return [result("Domain", "invalid_input", "Please provide a valid domain or URL.")]
    return [
        whois_lookup(domain),
        request_json("RDAP", "https://rdap.org/domain/" + quote(domain)),
        dns_lookup(domain),
        email_security_lookup(domain),
        tls_lookup(domain),
        certificate_transparency_lookup(domain),
        urlhaus_host_lookup(domain),
    ]


def ip_lookup(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return [result("IP Analysis", "invalid_input", "Invalid IP address.")]
    details = {"ip": str(address), "version": address.version, "is_private": address.is_private,
               "is_global": address.is_global, "is_loopback": address.is_loopback,
               "is_multicast": address.is_multicast, "is_reserved": address.is_reserved}
    output = [
        result("IP Analysis", "success", "IP address checked locally", details),
        request_json("IP Network / ASN", "https://ipwho.is/" + quote(str(address))),
        request_json("IP RDAP", "https://rdap.org/ip/" + quote(str(address))),
        urlhaus_host_lookup(str(address)),
    ]
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(str(address))
        output.append(result("Reverse DNS", "success", "Reverse DNS name retrieved",
                             {"hostname": hostname, "aliases": aliases, "addresses": addresses}))
    except OSError:
        output.append(result("Reverse DNS", "no_data", "No reverse DNS record found"))
    return output


def phone_lookup(value):
    try:
        parsed = phonenumbers.parse(value, None)
        details = {
            "international_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "country_calling_code": parsed.country_code,
            "possible": phonenumbers.is_possible_number(parsed),
            "valid_by_numbering_metadata": phonenumbers.is_valid_number(parsed),
            "region_metadata": geocoder.description_for_number(parsed, "en") or None,
            "carrier_metadata": carrier.name_for_number(parsed, "en") or None,
            "note": "Numbering metadata does not identify or verify the subscriber.",
        }
        return result("Phone Metadata", "success", "Processed number format and numbering metadata", details)
    except phonenumbers.NumberParseException as exc:
        return result("Phone Metadata", "invalid_input", f"Could not parse phone number: {exc}")


def email_lookup(value):
    if value.count("@") != 1:
        return result("Email Analysis", "invalid_input", "Invalid email address format.")
    local, domain = value.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        return result("Email Analysis", "invalid_input", "Please check the email address.")
    details = {"address": value, "domain": domain, "syntax_check": "passed",
               "note": "Syntax and DNS checks cannot confirm that a mailbox exists or identify its owner."}
    try:
        details["mx_records"] = [str(item) for item in dns.resolver.resolve(domain, "MX", lifetime=4)]
        details["mail_domain_status"] = "MX records found"
        status = "success"
    except Exception as exc:
        details["mx_records"] = []
        details["mail_domain_status"] = "MX lookup unsuccessful"
        details["dns_note"] = str(exc)
        status = "partial"
    return result("Email Analysis", status, "Checked address syntax and domain MX records", details)


def hash_lookup(value):
    value = str(value).strip()
    if not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
        return result("MalwareBazaar", "invalid_input", "Expected an MD5, SHA-1, or SHA-256 hash.")
    return request_json("MalwareBazaar", "https://mb-api.abuse.ch/api/v1/",
                        method="POST", data={"query": "get_info", "hash": value})


def clean_html_text(page_html):
    page_html = re.sub(r"(?is)<(script|style|noscript|svg|nav|footer|header|form)\b[^>]*>.*?</\1>", " ", page_html)
    page_html = re.sub(r"(?i)<br\s*/?>", "\n", page_html)
    page_html = re.sub(r"(?i)</(p|div|li|h[1-6]|article|section)>", "\n", page_html)
    page_html = re.sub(r"(?s)<[^>]+>", " ", page_html)
    page_html = unescape(page_html)
    page_html = re.sub(r"[ \t\r\f\v]+", " ", page_html)
    page_html = re.sub(r"\n\s*\n+", "\n", page_html)
    return page_html.strip()


def fetch_public_page(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return {"status": "blocked", "title": "", "text": ""}
        response = SESSION.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=True, stream=True)
        if response.status_code >= 400:
            status = f"http_{response.status_code}"
            response.close()
            return {"status": status, "title": "", "text": ""}
        content_type = response.headers.get("Content-Type", "").lower()
        if not any(kind in content_type for kind in ("text/html", "application/xhtml+xml", "text/plain")):
            response.close()
            return {"status": "unsupported_content_type", "title": "", "text": ""}
        chunks, size = [], 0
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            chunk = chunk[:config.MAX_PAGE_BYTES - size]
            chunks.append(chunk)
            size += len(chunk)
            if size >= config.MAX_PAGE_BYTES:
                break
        encoding = response.encoding or "utf-8"
        response.close()
        html = b"".join(chunks).decode(encoding, errors="replace")
        match = re.search(r"(?is)<title\b[^>]*>(.*?)</title>", html)
        title = clean_html_text(match.group(1)) if match else ""
        return {"status": "fetched", "title": title, "text": clean_html_text(html)[:config.MAX_PAGE_TEXT]}
    except Exception as exc:
        return {"status": "fetch_error", "title": "", "text": str(exc)[:500]}


def search_lookup(value, max_results=None):
    max_results = max_results or config.MAX_SEARCH_RESULTS
    found, seen, errors = [], set(), []
    try:
        with DDGS() as search:
            for item in search.text(str(value), max_results=max_results, safesearch="moderate"):
                url = (item.get("href") or "").strip()
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https") or not parsed.netloc:
                    continue
                key = (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"))
                if key in seen:
                    continue
                seen.add(key)
                found.append({"title": item.get("title") or "Untitled", "url": url,
                              "snippet": item.get("body") or "", "page_text": "", "page_status": "not_fetched"})
    except Exception as exc:
        errors.append(str(exc))
    for item in found:
        page = fetch_public_page(item["url"])
        item["page_status"], item["page_text"] = page["status"], page["text"]
        if page["title"] and item["title"] == "Untitled":
            item["title"] = page["title"]
    return result("Public Web Search", "success" if found else "no_results",
                  f"Found {len(found)} unique pages",
                  {"query": str(value), "results": found, "errors": errors,
                   "note": "Search results are leads for review, not proof of identity or ownership."})


def collect(value, kind):
    if kind in ("domain", "url"):
        return domain_lookup(value, kind)
    if kind == "ip":
        return ip_lookup(value)
    if kind == "phone":
        return [phone_lookup(value)]
    if kind == "email":
        return [email_lookup(value)]
    if kind == "hash":
        return [hash_lookup(value)]
    return [search_lookup(value)]
