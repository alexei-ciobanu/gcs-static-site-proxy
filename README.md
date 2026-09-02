# gcs-static-site-proxy

Serve one private Google Cloud Storage static-site prefix, or an explicit
catalog of prefixes, through a renewable, read-only local proxy. The GCS bucket
remains private: the proxy uses the operator's Application Default Credentials
(ADC) and exposes only explicitly configured object prefixes.

> **Status:** alpha. Review the publication-prefix and network-access security
> model before using the proxy with protected data.

## Requirements

- Python 3.11 or newer
- [`uv`](https://docs.astral.sh/uv/) for the recommended isolated invocation
- Google Cloud CLI for initializing or refreshing ADC
- `storage.objects.get` on the configured objects, normally through
  `roles/storage.objectViewer` or a stronger role

Initialize ADC:

```bash
gcloud auth login --update-adc
```

The proxy can also start without usable ADC. Its local URL serves a built-in
sign-in page and activates the configured GCS source after authentication
succeeds; no process restart is required.

## Install and run on localhost

Run the published package in an isolated environment:

```bash
uvx gcs-static-site-proxy@0.2.0 \
  --bucket private-site-bucket \
  --prefix team/sites/my-site
```

Alternatively, install it with `pip` and use either the command or Python
module entry point:

```bash
python -m pip install gcs-static-site-proxy==0.2.0
python -m gcs_static_site_proxy \
  --bucket private-site-bucket \
  --prefix team/sites/my-site
```

Run directly from a pinned public Git commit during development:

```bash
uvx --from 'git+https://github.com/alexei-ciobanu/gcs-static-site-proxy@COMMIT_SHA' \
  gcs-static-site-proxy \
  --bucket private-site-bucket \
  --prefix team/sites/my-site
```

The default listener is `127.0.0.1:8080`. It accepts only `GET` and `HEAD`,
rejects path traversal, and does not provide a general GCS proxy.
Outbound authentication and GCS requests use the operating system trust store,
including root certificate authorities installed through device management.

## Multiple sites and a landing page

Catalog mode serves a landing-page prefix at `/` and mounts explicitly
allowlisted site prefixes under `/sites/<slug>/`:

```bash
uvx gcs-static-site-proxy@0.2.0 \
  --bucket private-site-bucket \
  --catalog-prefix team/publication/static-sites
```

The catalog prefix must contain this exact object:

```text
team/publication/static-sites/.gcs-static-site-proxy-sites.json
```

Example:

```json
{
  "version": 1,
  "sites": [
    {
      "slug": "service-review",
      "title": "Service review",
      "prefix": "team/projects/service-review/publication/site"
    }
  ]
}
```

The landing page remains under the catalog prefix. Each mount maps only to its
declared prefix; unknown slugs fail closed, and neither catalog nor site
configuration objects are browser-accessible. Catalog editors can expose any
prefix that their proxy operator can read, so treat the catalog as a browser
publication allowlist and never mount a protected artifact prefix.

The proxy loads and validates the catalog and every site's CSP on the first
site request. The landing page uses the catalog prefix's
`.gcs-static-site-proxy.json`; each mounted site uses the same well-known
filename under its own prefix. Explicit CLI CSP overrides apply to all mounts.
Until source resolution succeeds, catalog routes remain inactive and no GCS
site content is served.

Path-mounted sites share a browser origin. Per-response CSPs remain distinct,
but a script running in one mounted site can make same-origin requests to other
mounted sites. Use one catalog only for sites approved for the same audience;
use separate origins when stronger isolation is required.

## Site security configuration

Unless overridden, the proxy requests this exact object when resolving the
site source:

```text
<prefix>/.gcs-static-site-proxy.json
```

Example:

```json
{
  "version": 1,
  "contentSecurityPolicy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "browserCache": "revalidate"
}
```

If it is absent, a strict built-in policy is used. An invalid, inaccessible or
unreachable configuration produces a fail-closed HTTP 502 response and is
reported in the proxy log; later requests can retry resolution. The active
source, generation and SHA-256 are printed after resolution succeeds.

`browserCache` is optional and supports `no-store` (the default) or
`revalidate`. Revalidation keeps HTML, extensionless objects and
proxy-controlled responses at `private,no-store`. Eligible non-HTML objects
with filename extensions use `private,no-cache`; the proxy forwards browser
`If-None-Match` and `If-Modified-Since` validators to GCS and relays unchanged
responses as HTTP 304 without downloading their bodies. If a conditional GCS
response omits its content type or identifies its representation as HTML, the
proxy retries it unconditionally; HTML is served as `private,no-store`.

Unlike `no-store`, `private,no-cache` permits the browser to retain private
object bytes in its local cache. It prevents shared-cache reuse and requires a
successful GCS revalidation before normal browser reuse, so revoked or expired
credentials are not hidden by a fresh cache entry. Enable it only when local
browser storage is suitable for the site's publication classification.

Without an explicit CLI mode, each prefix uses its own GCS configuration and
falls back to the strict built-in policy when that object is absent. The
mutually exclusive global modes are:

- `--csp-override-file PATH` applies one exact local policy to every route;
- `--strict-csp` applies the strict built-in policy to every route; and
- `--no-csp` disables CSP on every route.

In catalog mode these options affect the landing page and every mounted site.
For a local override of only one site, run that prefix separately in
single-site mode.

The site's browser-cache setting is also resolved independently for the
landing page and each catalog mount. A global override is available for local
testing or deliberately uniform catalogs:

```bash
--browser-cache revalidate
```

`--no-csp` disables only CSP. The proxy continues to send `no-referrer`,
`nosniff`, and frame-denial headers.

## Network access

Loopback is the safe default. Explicit non-loopback binding enables network
mode:

```bash
uvx gcs-static-site-proxy@0.2.0 \
  --bucket private-site-bucket \
  --prefix team/sites/my-site \
  --bind 0.0.0.0
```

Network mode generates a process-lifetime access token. Opening the printed
tokenized URL exchanges it for an HttpOnly, SameSite session cookie. IP-literal
Host values are accepted when they match the local destination address;
machine hostnames are detected automatically. Use `--allow-host HOST` for an
additional DNS alias.

The cookie is intentionally a browser-session cookie rather than a persistent
credential. If the browser is restarted while the proxy remains running, open
the printed tokenized URL again.

Anyone who has the token and can reach the listener can read the site using
the operator's GCS permissions. Plain HTTP does not protect content from
network interception. Supply both options for HTTPS:

```bash
--tls-cert certificate.pem --tls-key private-key.pem
```

Remote visitors cannot launch the local ADC reauthentication command.

## Local development

```bash
uv sync --dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check src
uv build --no-sources
```

## License

MIT
