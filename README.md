# vuln-mosaic-tap

**TAP Vuln Mosaic: fetches public vulnerability data into local stores that tooling reads without any live lookup.**

> Status: pre-spec (2026-10-16). No code yet; the specification is being written and will land first.

## What this plugin will own

A standalone, near-pure-Python collector that keeps local copies of public vulnerability data (CVE
records, the CISA KEV catalog, EPSS scores, NVD and OSV records) and a small read function for other
modules. It does not scan, match, or write findings.

## What lives elsewhere

- Scanning and matching: grype-tap. KEV for vulnerabilities Grype matched stays with grype-tap.
- The vulnerability vocabulary on the grid: compliance_core.
