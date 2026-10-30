# Juice Shop ground truth for the intrusive probes (checked against public Juice Shop documentation)

These notes exist so the probe results can be judged honestly, including their expected misses.

## Reflected XSS - search field
Juice Shop's own test suite sends `<iframe src="javascript:alert('xss')">` into the search box and
expects it rendered unsafely. Community write-ups describe the vulnerable parameter as the product
search query, surfaced at `/#/search?q=...` in the single-page app and backed by
`GET /rest/products/search?q=...` on the server. **Expected: our reflect_probe against
`/rest/products/search` param `q` SHOULD show a 'raw' signal** if the server echoes the query
unescaped in its JSON/error response.

## DOM XSS - search field (separate challenge from the above)
The official solution for the "DOM XSS" challenge uses a *different* payload,
`<iframe src="javascript:alert(`xss`)">` entered in the same search box, exploiting an Angular
`bypassSecurityTrustHtml` call client-side. **Expected: our probe CANNOT detect this.** It never
runs a browser or JavaScript engine, so it has no way to observe DOM rendering. This is a known,
accepted gap - note it in writeups rather than treat it as a false negative of the technique.

## SQL injection - login form
Public walkthroughs describe the "Login Admin" challenge as a SQL injection against the login
endpoint's email field (e.g. `' OR 1=1--`), which bypasses authentication.

We DO target the login endpoint (`POST /rest/user/login`, field `email`), but ONLY with
quote-breaking values (`'`, `''`) compared against a control - never a tautology payload. A
'signal' result (a different status/length when the quote isn't escaped) indicates the field is
probably not using parameterized queries, WITHOUT the probe itself ever constructing a working
bypass. The response body is discarded unread by the tool; no session token is captured.

If a signal is observed, the finding's "Suggested next step" names standard boolean-bypass
payloads a HUMAN can test manually (browser or Burp Repeater) to confirm actual impact. The agent
itself never sends such a payload. This line (signal detection only, no agent-performed
exploitation) is a standing project boundary, not a placeholder to be removed later.

## What "passing" looks like for this milestone
- reflect_probe against `/rest/products/search?q=`: raw signal expected.
- sqli_probe against the same endpoint: a signal is plausible per third-party write-ups, but
  unconfirmed by us - record whatever is observed and do not force bench numbers to match
  someone else's prose.
- DOM XSS, stored XSS, and the login-form SQL injection are explicitly OUT of this milestone's
  reach; do not read a lack of a finding there as the tool failing.
