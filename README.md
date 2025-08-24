# ruyaml <= 0.91.0 - Remote Code Execution (RCE)

This repository contains a security advisory for the `ruyaml` package (PyPI).  
The issue allows **Remote Code Execution (RCE)** if `ruyaml.load()` is used with untrusted YAML input.

## Details
- **Affected Product:** ruyaml
- **Affected Version:** <= 0.91.0
- **Vulnerability Type:** Remote Code Execution (RCE) via unsafe `load()`
- **Severity:** Critical
- **CVSS Score:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Related CVEs:** CVE-2019-20478 (ruamel.yaml), CVE-2017-18342 (PyYAML)

## Impact
Successful exploitation allows attackers to execute arbitrary system commands,
potentially leading to full compromise of the affected host.

## Files
- [`report/report.md`](./report/report.md) – Full vulnerability report
- [`report/poc.py`](./report/poc.py) – Proof of Concept script
- [`report/poc.png`](./report/poc.png) – Screenshot of PoC
- [`report/output.png`](./report/output.png) – Execution result

## Mitigation
- Use `ruyaml.safe_load()` instead of `ruyaml.load()` when parsing untrusted input
- Explicitly specify a safe loader (e.g., `ruyaml.load(data, Loader=ruyaml.SafeLoader)`)
- Apply input validation before processing user-supplied YAML

## Disclosure
- **Status:** Under responsible disclosure  
- **Disclosure Date:** 24 August 2025  
- **Reporter:** Manopakorn Kooharueangrong (Whyshealwaysbrokeme)
