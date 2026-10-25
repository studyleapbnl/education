# Study LEAP - security & operations runbook (v6.2)

Deploy order whenever worker.js, Code.gs and the website all change:
**1. worker.js (GitHub push)  ->  2. Code.gs (paste + "New version")  ->  3. website zip (public_html) + purge Cloudflare cache.**

Secrets that must exist
| Where | Name | Notes |
|---|---|---|
| Cloudflare Worker (Secret) | `OTP_SECRET` | random 32+ chars; same value as Apps Script `UPLOAD_SECRET` |
| Cloudflare Worker (Secret) | `TURNSTILE_SECRET` | must come from the SAME widget as the site key in the pages |
| Cloudflare Worker (Secret) | `CRM_SECRET`, `WHATSAPP_TOKEN`, `EMAILJS_*`, ... | unchanged |
| Apps Script > Script Properties | `UPLOAD_SECRET` | same value as `OTP_SECRET` |

## 1. Custom API domain (api.studyleap.in)
The website already tries `https://api.studyleap.in` first and falls back to the old `workers.dev` address
automatically, so you can do this at any time, with no downtime.
1. Cloudflare > Workers & Pages > **education** > Settings > **Domains & Routes** > Add > **Custom domain** > `api.studyleap.in`.
   (The `studyleap.in` zone must be in the same Cloudflare account. If it says the zone was not found, stop - the
   fallback keeps everything working on workers.dev.)
2. Wait ~1 minute, then open `https://api.studyleap.in/health` - you should see `{"ok":true,...}`.
3. Optional edge protection (Security > WAF > Rate limiting rules): hostname `api.studyleap.in`, path `/otp/send`,
   5 requests per minute per IP, action Block. This only works on the custom domain, not on workers.dev.
4. Later, when you are happy: Worker > Settings > Domains & Routes > disable the workers.dev route, and remove the
   fallback host from `api.js`.

## 2. Alerts
* Apps Script now e-mails studyleapbnl@gmail.com ("[Study LEAP] Upload service problem") when uploads fail for an
  unexpected reason (max 3 per hour, no student data inside). Run `testAlert()` once to confirm it arrives.
* Uptime e-mail: create a free monitor (UptimeRobot / Better Stack) for `https://api.studyleap.in/health`, interval 5 min.
* Cloudflare > Notifications: add "Workers" / "Health" style notifications that your plan offers, to the same address.
* WhatsApp: Meta Business Settings > Billing: set a spending alert; Account quality: keep an eye on the quality rating.

## 3. Protect the CRM page with Cloudflare Access
1. Cloudflare Zero Trust > Access > Applications > Add > **Self-hosted**.
2. Domain `studyleap.in` (and `www.studyleap.in`), path `leads_v3.html`.
3. Policy "Team": Action Allow, Include > Emails > your own address(es); login method One-time PIN.
4. Test in a private window: you must be asked for an e-mail PIN before the page loads.
The page also sends `noindex`/`no-store` headers (see .htaccess). Keep using the CRM secret for the API calls.

## 4. Turnstile: when to switch strict mode on
1. Submit each form once: home hero form, contact form, B2B form, upload-page OTP.
2. Open (PowerShell):
   `Invoke-RestMethod -Headers @{'X-CRM-Secret'='YOUR_CRM_SECRET'} https://api.studyleap.in/admin/status | ConvertTo-Json -Depth 6`
   (use the workers.dev address if the custom domain is not live yet).
3. Read `turnstile.readyForStrict` and `turnstile.recommendation`. It turns true after 3+ verified tokens and no failures.
4. When true: in `wrangler.toml` uncomment `TURNSTILE_REQUIRED = "true"` and push to GitHub.
5. Rollback: comment the line again and push. `blocked` in the status output = visitors that were refused.

## 5. Accounts
Turn on 2-step verification (security key or authenticator app, not SMS) for: the Google account that owns
Drive/Apps Script, the Cloudflare account, the Meta Business account, the GitHub account, the EmailJS account.
Save backup codes offline.

## 6. CSP hashes (inline scripts)
Every page may run only its own inline <script> blocks. After you edit ANY inline script in ANY page, run
`python3 tools/update-csp-hashes.py` before uploading (`--check` shows whether pages are stale). If you forget, that
page's script is blocked and the page misbehaves. Inline `onclick="..."` attributes are still allowed.
