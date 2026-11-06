# WebGuard Lite

A small, beginner-friendly Python CLI that checks the presence of common HTTP security response headers on **one URL**. It is a passive, low-impact learning project—not a penetration-testing suite or a substitute for a security review.

## What it checks

- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Framing protection through X-Frame-Options or CSP `frame-ancestors`
- Strict-Transport-Security for HTTPS URLs

It reports whether each header was observed. Presence alone does not mean a policy is correctly configured or that a site is secure.

## Safe-use boundaries

Only check systems you own or have explicit permission to assess. The tool makes one ordinary HTTP GET request, does not read the response body, does not follow redirects, and does not crawl, authenticate, brute-force, exploit, or probe ports. Use it gently and follow the target site's rules. A redirect is reported as the response to the original URL rather than followed to another host.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Run

```bash
python3 webguard.py https://example.com
```

Choose a timeout between 0.5 and 30 seconds (default: 8):

```bash
python3 webguard.py https://example.com --timeout 5
```

Save a JSON report as well as printing the summary:

```bash
python3 webguard.py https://example.com --json report.json
```

The report omits URL query strings and fragments to reduce the chance of copying tokens into a saved report.

## Test

```bash
python3 -m unittest discover -s tests -v
```

The tests use synthetic headers and do not make network requests.

## Limitations

WebGuard Lite checks only a short list of response-header names. It does not assess the strength or correctness of policy values, TLS configuration, application behavior, cookies, or other security controls. A missing header is a prompt for review, not proof of a vulnerability; a present header is not proof that the site is safe.
