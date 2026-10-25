# BLADE OSINT

**BLADE OSINT** is a desktop application for collecting and organizing information from public sources. It combines domain, DNS, IP, TLS certificate, email metadata, file-hash reputation, and public web-search lookups in one dark-themed interface.

> This project is intended for lawful, defensive research and analysis of public information. Results can be incomplete or outdated and must be independently verified.

## Features

- Domain registration data through WHOIS and RDAP
- DNS records, including A, AAAA, MX, NS, TXT, CAA, SOA, SRV, DNSKEY, and DS
- SPF and DMARC record checks
- TLS certificate metadata and SHA-256 fingerprint
- Certificate Transparency search through crt.sh
- IP metadata, RDAP, reverse DNS, and URLhaus host lookup
- Email syntax and MX-record checks
- Phone-number formatting and numbering metadata
- MD5, SHA-1, and SHA-256 lookups through MalwareBazaar
- Public web search with limited page-text extraction
- Interactive relationship graph
- JSON and HTML report export

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Internet connection for external lookups

## Installation

### Windows

```powershell
git clone https://github.com/blade391off/BLADE-OSINT.git
cd BLADE-OSINT
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

If PowerShell blocks activation, run the interpreter directly:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe main.py
```

### Linux / macOS

```bash
git clone https://github.com/blade391off/BLADE-OSINT.git
cd BLADE-OSINT
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

## Usage

1. Choose a target type.
2. Enter a domain, URL, IP address, email, phone number, file hash, or search term.
3. Select **Run investigation**.
4. Review the source results and their status.
5. Export JSON or HTML, or open the relationship graph.

Some sources may rate-limit requests, change their APIs, or be temporarily unavailable. A missing DNS record or a failed lookup does not automatically prove that a security control is absent.

## Data and privacy

- The application sends lookup queries to third-party services listed in the source code.
- Public web pages may be fetched to extract a limited amount of text.
- Do not submit secrets, private credentials, or data you are not authorized to analyze.
- Review third-party service terms before use.
- No claim of ownership, identity, or malicious activity should be based on a single data point.

## Sources

- [ICANN Lookup](https://lookup.icann.org/)
- [RDAP](https://rdap.org/)
- [Google Public DNS](https://dns.google/)
- [Certificate Transparency / crt.sh](https://crt.sh/)
- [URLhaus](https://urlhaus.abuse.ch/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [IPWho.is](https://ipwho.is/)

Availability and API behavior depend on the external services.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
