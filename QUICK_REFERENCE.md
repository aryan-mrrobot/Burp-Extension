# XSS Hunter Pro - Quick Reference

## Highlights

- Full Scanner UI (`XSSHunterTab`) with status, progress, and logs
- Crawling with configurable depth and max URLs
- Per‑page parameter association and testing
- CSP and WAF detection with context‑aware payloads
- UI‑controlled parameter probing with editable wordlist

## Fast Start

1. Load `main.py` in Burp: Extender → Extensions → Add → Python
2. Open the "XSS Hunter" tab
3. Enter a target URL and set options
4. (Optional) Enable "Parameter Discovery" probing and edit wordlist
5. Start the scan and monitor status/progress

## Key UI Areas

- **Status & Progress**: Live updates during baseline, crawl, and testing
- **Discovered URLs**: Pages found via crawl (anchors, forms, robots/sitemap)
- **HTTP Traffic**: Requests/responses with status codes
- **Parameter Discovery**: Toggle probing; edit names (newline/space/comma separated)

## Tips

- Use crawl settings to broaden discovery: set depth and max URLs
- Keep probing wordlist focused (e.g., `q,name,id,search`) to reduce noise
- Results include the exact page (source URL) where each parameter was tested

## Troubleshooting

- Check Extender → Errors for Python/Jython issues
- Verify the target is reachable; scanner adds default ports where needed
- Timeouts: baseline (10s), per‑request (30s); large pages may take longer

## Commands

```powershell
# Validate workspace (Windows PowerShell)
Get-ChildItem "d:\project" -Recurse | Select-Object FullName
```
