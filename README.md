# vuln-mosaic-tap

**TAP Vuln Mosaic: fetches public vulnerability data into local stores that tooling reads without any live lookup.**

> Status: in development. The specification is `specs/spec-vuln-mosaic-v0.md`; requirements flip to `Implemented` as they land.

## What this plugin owns

A standalone, near-pure-Python collector that keeps local copies of public vulnerability data (CVE
records, the CISA KEV catalog, EPSS scores, GitHub advisories, NVD and OSV records) and a small read function for other
modules. It does not scan, match, or write findings.

## What lives elsewhere

- Scanning and matching: grype-tap. KEV for vulnerabilities Grype matched stays with grype-tap.
- The vulnerability vocabulary on the grid: compliance_core.

## Read first

`specs/spec-vuln-mosaic-v0.md`. The decisions and their evidence are in it; this README does not repeat them.

## Standing it up

Develop against a TAP session: `scripts/spawn-session.sh <label> --from 'git+https://github.com/unified-systems-com/vuln-mosaic-tap@<commit>#ci' --dev-plugins vuln_mosaic`, then run `pytest --pyargs tap_plugin.vuln_mosaic` inside the session's `web` container.
