# krynox-captcha-spring-boot-starter

Official [**Krynox Captcha**](https://krynox.net) starter for **Spring Boot 3** — an auto-configured
verify filter plus a widget embed helper. Privacy-first, proof-of-work CAPTCHA. Java 17+.

```xml
<dependency>
  <groupId>net.krynox</groupId>
  <artifactId>krynox-captcha-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Configure

```yaml
# application.yml
krynox:
  secret: ${KRYNOX_SECRET_KEY}   # kcps_… — required to activate
  paths: [/signup, /contact]     # URL patterns to protect (nothing enforced until set)
```

That's it. The auto-configured filter verifies the solved token before protected requests reach your
controllers — a `403` on failure, otherwise it continues and exposes the result as a request
attribute. Only `POST`/`PUT`/`PATCH`/`DELETE` are enforced by default.

The token is read from the `krynox-captcha` request parameter (a form field — no body-stream
consumption) and falls back to the `X-Krynox-Captcha` header for fetch/API clients.

## Read the result in a controller

The `KrynoxResult` is available as the `krynox` request attribute:

```java
@PostMapping("/signup")
String signup(@RequestAttribute("krynox") KrynoxResult k) {
  if ("high".equals(k.risk()) || k.reasons().contains("tor-exit")) {
    // add friction: email verification, manual review, …
  }
  if (k.agent() != null && k.agent().verified() && k.agent().allowlisted()) {
    // a trusted, verified AI crawler
  }
  return "welcome";
}
```

`KrynoxResult`: `success`, `score`, `risk`, `hostname`, `challengeTs`, `errorCodes`, `reasons`,
`agent` (`verified`, `name`, `allowlisted`), `human` (`attested`, `method`, `issuer`).

## Widget embed

`KrynoxWidget.tag(sitekey)` returns the loader `<script>` + `<krynox-captcha>` element. In Thymeleaf:

```html
<form method="post" action="/signup">
  <div th:utext="${T(net.krynox.captcha.spring.KrynoxWidget).tag('kcpt_your_site_key')}"></div>
  <button type="submit">Sign up</button>
</form>
```

## Configuration reference (`krynox.*`)

| Property | Default | Notes |
| --- | --- | --- |
| `krynox.secret` | — | Your `kcps_…` secret key. **Required** for the starter to activate. |
| `krynox.paths` | (empty) | Servlet URL patterns to protect (e.g. `/signup`, `/api/*`). Empty → filter inert. |
| `krynox.methods` | `POST,PUT,PATCH,DELETE` | Methods to enforce on. |
| `krynox.api-host` | `https://api.krynox.net` | Data-plane host (self-hosting). |
| `krynox.field` | `krynox-captcha` | Request parameter carrying the token. |
| `krynox.header` | `X-Krynox-Captcha` | Header checked when the parameter is absent. |
| `krynox.timeout-ms` | `5000` | Per-attempt request timeout. |
| `krynox.retries` | `2` | Transient-failure (network/429/5xx) retries; a retried single-use token replays the first outcome via an idempotency key. |
| `krynox.trusted-proxy-header` | — | Optional edge-overwritten client-IP header. Disabled by default; prefer Spring Boot/Tomcat trusted-proxy configuration so `getRemoteAddr()` is resolved safely. |
| `krynox.enabled` | `true` | Master switch. |

Need custom logic (e.g. verify inside a service)? Inject the auto-configured `KrynoxVerifier` bean
and call `verifier.verify(token, remoteIp)`.

## Reliability

Transient failures (network, `429`, `5xx`) are retried automatically with exponential backoff.
Because a captcha token is single-use, a retried verify carries an **idempotency key** so the retry
replays the first outcome instead of failing the now-consumed token.

## Honeypot

Enable **Honeypot** for the site in the Krynox dashboard and the widget injects an invisible decoy
field (`krynox-hp`) that only bots fill in. The filter forwards it to `/siteverify` as `honeypot`
automatically (override the parameter name with `krynox.honeypot-field`) — the data plane then floors
the score (report mode) or rejects with `honeypot-tripped` (enforce mode). See the
[Honeypot docs](https://docs.krynox.net/server-side/honeypot/).

MIT licensed. Docs: <https://docs.krynox.net>
