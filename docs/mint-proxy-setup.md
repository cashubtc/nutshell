# Configuring the mint behind a proxy

The mint uses the same client address for HTTP and WebSocket rate limits.
`MINT_FORWARDED_ALLOW_IPS` lists the proxies allowed to forward that address.
Use the address the mint sees on the incoming connection.

## One proxy on the same host

If nginx receives connections directly from clients and connects to the mint at
`127.0.0.1`, the mint's defaults work as-is. Add this directive to the nginx
location that already forwards requests to the mint.

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
```

Reload nginx after changing its configuration.

## Other deployments

| Deployment | Mint configuration |
| --- | --- |
| Direct connections | Set `MINT_RATE_LIMIT_PROXY_TRUST=FALSE` to use the connecting client's IP. |
| Proxy in another container or on another host | Set `MINT_FORWARDED_ALLOW_IPS` to the proxy's IP as seen by the mint, for example `MINT_FORWARDED_ALLOW_IPS=10.0.0.5`. Separate IPs or trusted proxy networks with commas. |
| Cloudflare | Allowlist the ingress that connects to the mint. To prefer `CF-Connecting-IP`, set `MINT_TRUST_CLOUDFLARE_CONNECTING_IP=TRUE` only when every allowlisted ingress verifies that header. |
| Unix socket | Run `poetry run mint --uds=/run/cashu/mint.sock` and set `MINT_FORWARDED_ALLOW_IPS=/run/cashu/mint.sock`. Restrict access to the socket and its directory to the mint and trusted proxy. |

Use `*` only when every connection to the mint comes through a trusted proxy.
If you launch Uvicorn directly, pass `--no-proxy-headers` to let the mint apply
its own proxy settings.

## Verify the setup

Restart the mint after editing its `.env`, or recreate its container with the
updated environment. From two different public IPs, request `/v1/info` through
the normal public mint URL. Each request should show its client's IP in the
mint access log. If both show the proxy's IP, check which address connects to
the mint and which client address the proxy forwards.
