# Redirectors

A redirector is a lightweight landing page hosted on a separate domain that filters bot traffic before forwarding real victims to the phishing server. The lure URL points to the redirector, not the phishing server directly. This keeps the phishing infrastructure hidden from automated scanners, URL sandboxes, and security crawlers.

## Why use a redirector

- **IP separation** — scanners that follow the lure URL only see the redirector's IP (a shared CDN), never the phishing server
- **Bot filtering** — challenges like Cloudflare Turnstile block headless browsers and automated tools; only real browsers reach the phishing server
- **Domain reputation** — the redirector can be hosted on a high-reputation platform (Cloudflare Pages, Netlify, S3) that is unlikely to be blocked

## Flow

```txt
Victim clicks lure → Redirector (clean CDN domain)
                        ↓ passes bot challenge
                      Phishing server (miraged)
```

## Deployment

The redirector is a static HTML page — deploy it to any static hosting provider. The phishing server has no knowledge of the redirector; the redirector simply redirects the browser to the lure URL after the challenge passes.

1. Choose a hosting provider (Cloudflare Pages, Netlify, GitHub Pages, S3 + CloudFront, etc.)
2. Copy an example from `examples/redirectors/`
3. Replace the placeholder values (site key, lure URL)
4. Deploy to the hosting provider
5. Use the redirector URL as the link you send to targets

## Examples

The examples below demonstrate individual techniques. In practice, combine them — e.g., a file share pretext page that triggers a Turnstile challenge on click, then redirects to the lure URL.

### Cloudflare Turnstile

`examples/redirectors/turnstile.html` — runs a Cloudflare Turnstile challenge in invisible mode before redirecting. Bots fail the challenge and never reach the phishing server.

Setup:

1. Create a Turnstile site in the [Cloudflare dashboard](https://dash.cloudflare.com/?to=/:account/turnstile)
2. Set the domain to your redirector's hosting domain
3. Set widget mode to **Invisible**
4. Copy the site key into the HTML file
5. Replace `LURE_URL` with your phishing lure URL

### File share pretext

`examples/redirectors/file-share.html` — mimics a file sharing notification ("Someone shared a file with you"). Gives the victim a reason to click through, and discourages manual investigation by security teams who may see the link.

Setup:

1. Replace `SENDER_NAME` with a convincing sender name
2. Replace `FILE_NAME` with a convincing filename
3. Replace `LURE_URL` with your phishing lure URL
