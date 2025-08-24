# ruyaml <= 0.91.0 - Remote Code Execution (RCE)

This repository contains a security advisory for `ruyaml` package (PyPI).
The issue allows **Remote Code Execution (RCE)** if `ruyaml.load()` 
is used with untrusted YAML input.

## Details
- Affected Product: ruyaml
- Affected Version: <= 0.91.0
- Vulnerability Type: Remote Code Execution (RCE)
- Related CVEs: CVE-2019-20478 (ruamel.yaml), CVE-2017-18342 (PyYAML)

## Files
- `report/report.md` - Full vulnerability report
- `report/poc.py` - Proof of Concept
- `report/poc.png` - Screenshot of PoC
- `report/output.png` - Execution result

## Disclosure
- Status: Under responsible disclosure
- Disclosure Date: 25 August 2025
