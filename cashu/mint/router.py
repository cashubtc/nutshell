import asyncio
import html
import time

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from loguru import logger

from ..core.errors import KeysetNotFoundError
from ..core.models import (
    GetInfoResponse,
    KeysetsResponse,
    KeysetsResponseKeyset,
    KeysResponse,
    KeysResponseKeyset,
    PostCheckStateRequest,
    PostCheckStateResponse,
    PostMeltQuoteRequest,
    PostMeltQuoteResponse,
    PostMeltRequest,
    PostMintBatchRequest,
    PostMintBatchResponse,
    PostMintQuoteCheckRequest,
    PostMintQuoteRequest,
    PostMintQuoteResponse,
    PostMintRequest,
    PostMintResponse,
    PostRestoreRequest,
    PostRestoreResponse,
    PostSwapRequest,
    PostSwapResponse,
)
from ..core.settings import settings
from ..mint.startup import ledger
from .cache import RedisCache
from .limit import limit_websocket, limiter

router = APIRouter()
redis = RedisCache()


CSS = """
:root {
  --bg: #000;
  --surface: #0e0e0e;
  --surface-2: #191919;
  --border: rgba(255,255,255,0.08);
  --border-section: rgba(255,255,255,0.06);
  --text-primary: #fff;
  --text-secondary: rgba(255,255,255,0.72);
  --text-muted: rgba(255,255,255,0.45);
  --text-faint: rgba(255,255,255,0.28);
  --green: #00d632;
  --green-soft: rgba(0, 214, 50, 0.1);
  --green-glow: rgba(0, 214, 50, 0.06);
  --red: #ff5555;
  --red-soft: rgba(255, 68, 68, 0.1);
  --yellow: #ffb800;
  --yellow-soft: rgba(255, 184, 0, 0.1);
  --radius: 16px;
  --radius-sm: 12px;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  background: var(--bg);
  color: var(--text-primary);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}

.page {
  max-width: 520px;
  margin: 0 auto;
  padding: 0 20px 100px;
}

/* ── Topbar ── */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  position: sticky;
  top: 0;
  background: rgba(0,0,0,0.88);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  z-index: 10;
}

.cashu-wordmark {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-muted);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 600;
  color: var(--green);
  background: var(--green-soft);
  padding: 5px 11px;
  border-radius: 20px;
}

.status-dot {
  width: 6px;
  height: 6px;
  background: var(--green);
  border-radius: 50%;
  animation: pulse 2.4s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

/* ── Hero ── */
.hero {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 40px 0 16px;
  position: relative;
}

.hero::before {
  content: '';
  position: absolute;
  top: 16px;
  left: 50%;
  transform: translateX(-50%);
  width: 180px;
  height: 180px;
  background: radial-gradient(circle, var(--green-glow) 0%, transparent 70%);
  pointer-events: none;
}

.avatar-ring {
  width: 88px;
  height: 88px;
  border-radius: 50%;
  padding: 2.5px;
  background: linear-gradient(135deg, var(--green) 0%, rgba(0,214,50,0.15) 100%);
  margin-bottom: 20px;
  position: relative;
  z-index: 1;
}

.avatar {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background: var(--surface-2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 34px;
  font-weight: 700;
  color: var(--green);
  overflow: hidden;
}

.avatar img { width: 100%; height: 100%; object-fit: cover; }

.mint-name {
  font-size: 30px;
  font-weight: 800;
  letter-spacing: -0.03em;
  text-align: center;
  line-height: 1.15;
  margin-bottom: 8px;
}

.mint-desc {
  font-size: 15px;
  font-weight: 400;
  color: var(--text-secondary);
  text-align: center;
  line-height: 1.5;
  max-width: 380px;
}

.mint-desc-long {
  font-size: 14px;
  font-weight: 400;
  color: var(--text-muted);
  text-align: center;
  line-height: 1.5;
  max-width: 380px;
  margin-top: 4px;
  font-style: italic;
}

.version-chip {
  font-size: 11px;
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  font-weight: 500;
  color: var(--text-muted);
  background: var(--surface);
  padding: 5px 12px;
  border-radius: 20px;
  border: 1px solid var(--border);
  margin-top: 14px;
}

/* ── MOTD ── */
.motd {
  background: var(--yellow-soft);
  border: 1px solid rgba(255,184,0,0.12);
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  margin: 24px 0 0;
}

.motd-label {
  font-size: 10px;
  font-weight: 700;
  color: var(--yellow);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 4px;
}

.motd-text {
  font-size: 14px;
  color: rgba(255,255,255,0.85);
  line-height: 1.5;
}

/* ── Disabled banners ── */
.disabled-banner {
  background: var(--red-soft);
  border: 1px solid rgba(255,68,68,0.12);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  margin-top: 16px;
  font-size: 14px;
  font-weight: 500;
  color: var(--red);
  text-align: center;
}

/* ── URL section ── */
.url-section { margin-top: 28px; }

.url-bar {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.url-text {
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  font-size: 13px;
  color: var(--text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}

.extra-urls { margin-top: 8px; display: flex; flex-direction: column; gap: 6px; }

.extra-url {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 14px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.extra-url .url-text { font-size: 11px; }

.url-label {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-faint);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  flex-shrink: 0;
}

/* ── Detail card ── */
.detail-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-top: 28px;
  overflow: hidden;
}

.card-section-header {
  padding: 18px 20px 0;
  font-size: 15px;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: -0.01em;
}

.card-section-header.has-rule {
  border-top: 1px solid var(--border-section);
  margin-top: 16px;
  padding-top: 18px;
}

.detail-row {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  padding: 7px 20px;
  gap: 16px;
}

.detail-row:first-child,
.card-section-header + .detail-row {
  padding-top: 12px;
}

.detail-row:last-child,
.detail-row + .card-divider {
  padding-bottom: 4px;
}

.detail-row.row-last {
  padding-bottom: 16px;
}

.detail-label {
  font-size: 14px;
  font-weight: 400;
  color: var(--text-secondary);
  flex-shrink: 0;
}

.detail-value {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  text-align: right;
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.detail-value-mono {
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
}

/* Tags */
.tag {
  font-size: 12px;
  font-weight: 600;
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  padding: 4px 11px;
  border-radius: 20px;
  background: var(--surface-2);
  color: var(--text-primary);
  border: 1px solid var(--border);
  display: inline-block;
  text-transform: uppercase;
}

.tag-red {
  background: var(--red-soft);
  color: var(--red);
  border-color: rgba(255,68,68,0.12);
}

/* ── Features grid ── */
.features-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  margin: 0;
}

.feature {
  padding: 12px 20px;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  border-bottom: 1px solid var(--border-section);
  border-right: 1px solid var(--border-section);
}

.feature:nth-child(2n) { border-right: none; }
.feature:nth-last-child(-n+2) { border-bottom: none; }
.feature:last-child:nth-child(odd) { border-right: none; }

.feature-dot {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--green-soft);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin-top: 2px;
}

.feature-dot svg { width: 10px; height: 10px; }

.feature-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
  line-height: 1.3;
}

/* ── Contact ── */
.contact-chips { display: flex; gap: 8px; flex-wrap: wrap; padding: 4px 20px 18px; }

.contact-chip {
  font-size: 12px;
  font-weight: 600;
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  color: var(--text-primary);
  background: var(--surface-2);
  border: 1px solid var(--border);
  padding: 4px 11px;
  border-radius: 20px;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.contact-chip svg { width: 12px; height: 12px; opacity: 0.5; }

/* ── Pubkey row ── */
.pubkey-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 20px 18px;
}

.pubkey-mono {
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  font-size: 11px;
  color: var(--text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}

/* ── Info tip ── */
.info-tip {
  margin-top: 28px;
  padding: 18px 20px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.info-tip-icon {
  width: 18px; height: 18px;
  flex-shrink: 0;
  color: var(--text-muted);
  margin-top: 2px;
}

.info-tip-text {
  font-size: 13.5px;
  color: var(--text-secondary);
  line-height: 1.6;
}

.info-tip-text a {
  color: var(--text-primary);
  font-weight: 600;
  text-decoration: none;
  border-bottom: 1px solid var(--text-faint);
}

/* ── Footer ── */
.footer {
  text-align: center;
  padding: 36px 0 20px;
  font-size: 12px;
  color: var(--text-faint);
}

.footer a {
  color: var(--text-muted);
  text-decoration: none;
}
"""


def format_limit(amount: int, unit: str) -> str:
    if amount >= 1_000_000:
        return f"{amount // 1_000_000}M {unit}"
    elif amount >= 1_000:
        return f"{amount // 1_000}K {unit}"
    else:
        return f"{amount} {unit}"


@router.get(
    "/",
    name="Mint Landing Page",
    summary="Landing page showing mint information and supported features.",
    response_class=HTMLResponse,
)
async def index(request: Request) -> HTMLResponse:
    mint_info = ledger.mint_info

    name = mint_info.name or "Nutshell Mint"
    description = mint_info.description or ""
    description_long = mint_info.description_long or ""
    motd = mint_info.motd or ""
    pubkey = mint_info.pubkey or ""
    version = mint_info.version or ""
    contact = mint_info.contact or []
    icon_url = mint_info.icon_url or ""

    # Base URL / Onion / Alt URLs
    urls = settings.mint_info_urls or [str(request.base_url).rstrip("/")]

    # Active Units
    units = sorted(list(set(keyset.unit.name.upper() for keyset in ledger.keysets.values() if keyset.active)))

    # Methods (Minting / Melting)
    mint_methods = []
    melt_methods = []
    backends_methods = sorted(list(set(getattr(m, "name", str(m)).upper() for m in ledger.backends.keys())))
    if not settings.mint_bolt11_disable_mint:
        mint_methods = backends_methods
    if not settings.mint_bolt11_disable_melt:
        melt_methods = backends_methods

    # Limits
    mint_limits = []
    if settings.mint_max_mint_bolt11_sat:
        mint_limits.append(format_limit(settings.mint_max_mint_bolt11_sat, "sat"))

    melt_limits = []
    if settings.mint_max_melt_bolt11_sat:
        melt_limits.append(format_limit(settings.mint_max_melt_bolt11_sat, "sat"))

    # Features (NUTs)
    supported_features = []
    nuts = mint_info.nuts or {}

    def is_nut_supported(nut_num: int) -> bool:
        if nut_num not in nuts:
            return False
        nut_val = nuts[nut_num]
        if isinstance(nut_val, dict):
            if nut_val.get("disabled", False) is True:
                return False
            return nut_val.get("supported", True) is True
        return True

    if is_nut_supported(7):
        supported_features.append((7, "Token state check"))
    if is_nut_supported(8):
        supported_features.append((8, "Lightning fee returns"))
    if is_nut_supported(9):
        supported_features.append((9, "Signature restore"))
    if is_nut_supported(10):
        supported_features.append((10, "Spending conditions"))
    if is_nut_supported(11):
        supported_features.append((11, "Pay-to-Pubkey"))
    if is_nut_supported(12):
        supported_features.append((12, "DLEQ proofs"))
    if is_nut_supported(14):
        supported_features.append((14, "HTLCs"))
    if is_nut_supported(15):
        supported_features.append((15, "Multi-path payments"))
    if is_nut_supported(17):
        supported_features.append((17, "WebSocket subscriptions"))
    if is_nut_supported(19):
        supported_features.append((19, "Cached responses"))
    if is_nut_supported(20):
        supported_features.append((20, "Signed mint quotes"))
    if is_nut_supported(21):
        supported_features.append((21, "Clear auth"))
    if is_nut_supported(22):
        supported_features.append((22, "Blind auth"))
    if is_nut_supported(29):
        supported_features.append((29, "Batched minting"))

    # Escape and prepare elements
    name_escaped = html.escape(name)
    avatar_letter = (name_escaped[0] if name_escaped else "M").upper()

    if icon_url:
        avatar_html = f'<img src="{html.escape(icon_url)}" alt="{name_escaped}">'
    else:
        avatar_html = avatar_letter

    units_html = "".join(f'<span class="tag">{html.escape(u)}</span>' for u in units)

    if settings.mint_bolt11_disable_mint:
        minting_html = '<span class="tag tag-red">disabled</span>'
    else:
        minting_html = "".join(f'<span class="tag">{html.escape(m)}</span>' for m in mint_methods)

    if settings.mint_bolt11_disable_melt:
        melting_html = '<span class="tag tag-red">disabled</span>'
    else:
        melting_html = "".join(f'<span class="tag">{html.escape(m)}</span>' for m in melt_methods)

    mint_limits_html = " · ".join(html.escape(lim) for lim in mint_limits) if mint_limits else ""
    melt_limits_html = " · ".join(html.escape(lim) for lim in melt_limits) if melt_limits else ""

    # Extra/onion URLs
    urls_html = ""
    if urls:
        primary_url_html = f'<div class="url-bar"><span class="url-text">{html.escape(urls[0])}</span></div>'
        if len(urls) > 1:
            extra_urls_items = []
            for url in urls[1:]:
                label = "TOR" if ".onion" in url.lower() else "ALT"
                extra_urls_items.append(
                    f'<div class="extra-url">'
                    f'<span class="url-label">{label}</span>'
                    f'<span class="url-text">{html.escape(url)}</span>'
                    f'</div>'
                )
            extra_urls_html = "".join(extra_urls_items)
            urls_html = f'<div class="url-section">{primary_url_html}<div class="extra-urls">{extra_urls_html}</div></div>'
        else:
            urls_html = f'<div class="url-section">{primary_url_html}</div>'

    # MOTD
    motd_html = ""
    if motd:
        motd_html = (
            f'<div class="motd">'
            f'<div class="motd-label">Mint notice</div>'
            f'<div class="motd-text">{html.escape(motd)}</div>'
            f'</div>'
        )

    # Disabled banners
    disabled_banners_html = ""
    if settings.mint_bolt11_disable_mint:
        disabled_banners_html += '<div class="disabled-banner">Minting is currently disabled</div>'
    if settings.mint_bolt11_disable_melt:
        disabled_banners_html += '<div class="disabled-banner">Melting is currently disabled</div>'

    # Features Grid
    features_html = ""
    if supported_features:
        features_items = []
        for nut_num, feature_name in supported_features:
            features_items.append(
                f'<div class="feature">'
                f'<div class="feature-dot">'
                f'<svg viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>'
                f'</div>'
                f'<span class="feature-name">{html.escape(feature_name)}</span>'
                f'</div>'
            )
        features_html = (
            f'<div class="card-section-header has-rule">Supported features</div>'
            f'<div style="padding-top:12px">'
            f'<div class="features-grid">{"".join(features_items)}</div>'
            f'</div>'
        )

    # Contacts
    contact_html = ""
    if contact:
        contact_items = []
        for c in contact:
            if isinstance(c, dict):
                c_method = c.get("method")
                c_info = c.get("info")
            else:
                c_method = getattr(c, "method", None)
                c_info = getattr(c, "info", None)
            if not c_method or not c_info:
                continue

            method_lower = c_method.lower()
            info_escaped = html.escape(c_info)
            method_escaped = html.escape(c_method)

            if method_lower == "email":
                contact_items.append(
                    f'<a class="contact-chip" href="mailto:{info_escaped}" target="_blank">'
                    f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22,4 12,13 2,4"/></svg>'
                    f'{info_escaped}'
                    f'</a>'
                )
            elif method_lower == "twitter":
                clean_info = c_info.lstrip("@")
                contact_items.append(
                    f'<a class="contact-chip" href="https://x.com/{html.escape(clean_info)}" target="_blank">'
                    f'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>'
                    f'{info_escaped}'
                    f'</a>'
                )
            elif method_lower == "nostr":
                contact_items.append(
                    f'<a class="contact-chip" href="https://njump.me/{info_escaped}" target="_blank">'
                    f'<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>'
                    f'{info_escaped}'
                    f'</a>'
                )
            else:
                contact_items.append(
                    f'<span class="contact-chip">{method_escaped}: {info_escaped}</span>'
                )
        if contact_items:
            contact_html = (
                f'<div class="card-section-header has-rule">Contact</div>'
                f'<div style="padding-top:12px">'
                f'<div class="contact-chips">{"".join(contact_items)}</div>'
                f'</div>'
            )

    # Public Key
    pubkey_html = ""
    if pubkey:
        pubkey_html = (
            f'<div class="card-section-header has-rule">Public key</div>'
            f'<div class="pubkey-row">'
            f'<span class="pubkey-mono">{html.escape(pubkey)}</span>'
            f'</div>'
        )

    # Detailed rows for units, minting, melting, limits
    details_rows_html = ""
    if units:
        details_rows_html += (
            f'<div class="detail-row" style="padding-top:14px">'
            f'  <span class="detail-label">Units</span>'
            f'  <div class="detail-value">{units_html}</div>'
            f'</div>'
        )

    details_rows_html += (
        f'<div class="detail-row">'
        f'  <span class="detail-label">Minting</span>'
        f'  <div class="detail-value">{minting_html}</div>'
        f'</div>'
    )
    details_rows_html += (
        f'<div class="detail-row">'
        f'  <span class="detail-label">Melting</span>'
        f'  <div class="detail-value">{melting_html}</div>'
        f'</div>'
    )

    if mint_limits_html:
        details_rows_html += (
            f'<div class="detail-row">'
            f'  <span class="detail-label">Mint limits</span>'
            f'  <span class="detail-value detail-value-mono">{mint_limits_html}</span>'
            f'</div>'
        )

    if melt_limits_html:
        details_rows_html += (
            f'<div class="detail-row row-last">'
            f'  <span class="detail-label">Melt limits</span>'
            f'  <span class="detail-value detail-value-mono">{melt_limits_html}</span>'
            f'</div>'
        )

    description_html = f'<div class="mint-desc">{html.escape(description)}</div>' if description else ""
    description_long_html = f'<div class="mint-desc-long">{html.escape(description_long)}</div>' if description_long else ""
    version_html = f'<div class="version-chip">{html.escape(version)}</div>' if version else ""

    # Full HTML markup
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <title>{name_escaped}</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
{CSS}
    </style>
</head>
<body>
    <div class="page">
        <!-- Topbar -->
        <div class="topbar">
            <span class="cashu-wordmark">Cashu Mint</span>
            <span class="status-badge">
                <span class="status-dot"></span>
                Online
            </span>
        </div>

        <!-- Hero -->
        <div class="hero">
            <div class="avatar-ring">
                <div class="avatar">
                    {avatar_html}
                </div>
            </div>
            <div class="mint-name">{name_escaped}</div>
            {description_html}
            {description_long_html}
            {version_html}
        </div>

        <!-- MOTD -->
        {motd_html}

        <!-- Disabled banners -->
        {disabled_banners_html}

        <!-- URL section -->
        {urls_html}

        <!-- Unified detail card -->
        <div class="detail-card">
            <!-- Mint details section -->
            <div class="card-section-header">Mint details</div>

            {details_rows_html}

            <!-- Supported features section -->
            {features_html}

            <!-- Contact section -->
            {contact_html}

            <!-- Public key section -->
            {pubkey_html}
        </div>

        <!-- Info tip -->
        <div class="info-tip">
            <div class="info-tip-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
            </div>
            <div class="info-tip-text">
                To use this mint, copy the mint URL above and add it to a Cashu-compatible wallet such as 
                <a href="https://wallet.cashu.me" target="_blank">Cashu.me</a>, 
                <a href="https://macadamia.cash" target="_blank">Macadamia</a>, or 
                <a href="https://www.minibits.cash" target="_blank">Minibits</a>.
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <div>
                Powered by 
                <a href="https://github.com/cashubtc/nutshell" target="_blank">Nutshell</a>
            </div>
            <div style="margin-top: 8px">
                <a href="https://iscashucustodial.com/" target="_blank">isCashuCustodial.com</a>
            </div>
        </div>
    </div>
</body>
</html>"""

    return HTMLResponse(content=html_content)


@router.get(
    "/v1/info",
    name="Mint information",
    summary="Mint information, operator contact information, and other info.",
    response_model=GetInfoResponse,
    response_model_exclude_none=True,
)
async def info() -> GetInfoResponse:
    logger.trace("> GET /v1/info")
    mint_info = ledger.mint_info
    return GetInfoResponse(
        name=mint_info.name,
        pubkey=mint_info.pubkey,
        version=mint_info.version,
        description=mint_info.description,
        description_long=mint_info.description_long,
        contact=mint_info.contact,
        nuts=mint_info.nuts,
        icon_url=mint_info.icon_url,
        tos_url=mint_info.tos_url,
        urls=settings.mint_info_urls,
        motd=mint_info.motd,
        time=int(time.time()),
    )


@router.get(
    "/v1/keys",
    name="Mint public keys",
    summary="Get the public keys of the newest mint keyset",
    response_description=(
        "All supported token values their associated public keys for all active keysets"
    ),
    response_model=KeysResponse,
)
async def keys():
    """This endpoint returns a dictionary of all supported token values of the mint and their associated public key."""
    logger.trace("> GET /v1/keys")
    keyset = ledger.keyset
    keyset_for_response = []
    for keyset in ledger.keysets.values():
        if keyset.active:
            keyset_for_response.append(
                KeysResponseKeyset(
                    id=keyset.id,
                    unit=keyset.unit.name,
                    active=keyset.active,
                    input_fee_ppk=keyset.input_fee_ppk,
                    keys={k: v for k, v in keyset.public_keys_hex.items()},
                    final_expiry=keyset.final_expiry,  # NEW: Include final expiry to align with NUT-02 PR #182
                )
            )
    return KeysResponse(keysets=keyset_for_response)


@router.get(
    "/v1/keys/{keyset_id}",
    name="Keyset public keys",
    summary="Public keys of a specific keyset",
    response_description=(
        "All supported token values of the mint and their associated"
        " public key for a specific keyset."
    ),
    response_model=KeysResponse,
)
async def keyset_keys(keyset_id: str) -> KeysResponse:
    """
    Get the public keys of the mint from a specific keyset id.
    """
    logger.trace(f"> GET /v1/keys/{keyset_id}")
    # BEGIN BACKWARDS COMPATIBILITY < 0.15.0
    # if keyset_id is not hex, we assume it is base64 and sanitize it
    try:
        int(keyset_id, 16)
    except ValueError:
        keyset_id = keyset_id.replace("-", "+").replace("_", "/")
    # END BACKWARDS COMPATIBILITY < 0.15.0

    keyset = ledger.keysets.get(keyset_id)
    if keyset is None:
        raise KeysetNotFoundError(keyset_id)

    keyset_for_response = KeysResponseKeyset(
        id=keyset.id,
        unit=keyset.unit.name,
        active=keyset.active,
        input_fee_ppk=keyset.input_fee_ppk,
        keys={k: v for k, v in keyset.public_keys_hex.items()},
        final_expiry=keyset.final_expiry,
    )
    return KeysResponse(keysets=[keyset_for_response])


@router.get(
    "/v1/keysets",
    name="Active keysets",
    summary="Get all active keyset id of the mind",
    response_model=KeysetsResponse,
    response_description="A list of all active keyset ids of the mint.",
)
async def keysets() -> KeysetsResponse:
    """This endpoint returns a list of keysets that the mint currently supports and will accept tokens from."""
    logger.trace("> GET /v1/keysets")
    keysets = []
    for id, keyset in ledger.keysets.items():
        keysets.append(
            KeysetsResponseKeyset(
                id=keyset.id,
                unit=keyset.unit.name,
                active=keyset.active,
                input_fee_ppk=keyset.input_fee_ppk,
                final_expiry=keyset.final_expiry,
            )
        )
    return KeysetsResponse(keysets=keysets)


@router.post(
    "/v1/mint/quote/bolt11",
    name="Request mint quote",
    summary="Request a quote for minting of new tokens",
    response_model=PostMintQuoteResponse,
    response_description="A payment request to mint tokens of a denomination",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def mint_quote(
    request: Request, payload: PostMintQuoteRequest
) -> PostMintQuoteResponse:
    """
    Request minting of new tokens. The mint responds with a Lightning invoice.
    This endpoint can be used for a Lightning invoice UX flow.

    Call `POST /v1/mint/bolt11` after paying the invoice.
    """
    logger.trace(f"> POST /v1/mint/quote/bolt11: payload={payload}")
    quote = await ledger.mint_quote(payload)
    resp = PostMintQuoteResponse(
        quote=quote.quote,
        request=quote.request,
        amount=quote.amount,
        unit=quote.unit,
        method=quote.method,
        state=str(quote.state.value),
        expiry=quote.expiry,
        pubkey=quote.pubkey,
        amount_paid=quote.amount_paid,
        amount_issued=quote.amount_issued,
        updated_at=quote.updated_at,
    )
    logger.trace(f"< POST /v1/mint/quote/bolt11: {resp}")
    return resp


@router.get(
    "/v1/mint/quote/bolt11/{quote}",
    summary="Get mint quote",
    response_model=PostMintQuoteResponse,
    response_description="Get an existing mint quote to check its status.",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def get_mint_quote(request: Request, quote: str) -> PostMintQuoteResponse:
    """
    Get mint quote state.
    """
    logger.trace(f"> GET /v1/mint/quote/bolt11/{quote}")
    mint_quote = await ledger.get_mint_quote(quote)
    resp = PostMintQuoteResponse(
        quote=mint_quote.quote,
        request=mint_quote.request,
        amount=mint_quote.amount,
        unit=mint_quote.unit,
        method=mint_quote.method,
        state=str(mint_quote.state.value),
        expiry=mint_quote.expiry,
        pubkey=mint_quote.pubkey,
        amount_paid=mint_quote.amount_paid,
        amount_issued=mint_quote.amount_issued,
        updated_at=mint_quote.updated_at,
    )
    logger.trace(f"< GET /v1/mint/quote/bolt11/{quote}")
    return resp


@router.post(
    "/v1/mint/quote/bolt11/check",
    name="Batch check mint quotes",
    summary="Batch check mint quotes",
    response_model=list[PostMintQuoteResponse],
    response_description="A list of mint quotes",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def mint_quote_check(
    request: Request, payload: PostMintQuoteCheckRequest
) -> list[PostMintQuoteResponse]:
    logger.trace(f"> POST /v1/mint/quote/bolt11/check: payload={payload}")
    quotes = await ledger.mint_quote_check(payload)
    resp = [
        PostMintQuoteResponse(
            quote=quote.quote,
            request=quote.request,
            amount=quote.amount,
            unit=quote.unit,
            method=quote.method,
            state=str(quote.state.value),
            expiry=quote.expiry,
            pubkey=quote.pubkey,
            amount_paid=quote.amount_paid,
            amount_issued=quote.amount_issued,
            updated_at=quote.updated_at,
        )
        for quote in quotes
    ]
    logger.trace(f"< POST /v1/mint/quote/bolt11/check: {resp}")
    return resp


@router.post(
    "/v1/mint/bolt11/batch",
    name="Batch mint tokens",
    summary="Batch mint tokens",
    response_model=PostMintBatchResponse,
    response_description="A list of blinded signatures that can be used to create proofs.",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def mint_batch(
    request: Request, payload: PostMintBatchRequest
) -> PostMintBatchResponse:
    logger.trace(f"> POST /v1/mint/bolt11/batch: payload={payload}")
    signatures = await ledger.mint_batch(payload)
    resp = PostMintBatchResponse(signatures=signatures)
    logger.trace(f"< POST /v1/mint/bolt11/batch: {resp}")
    return resp


@router.websocket("/v1/ws", name="Websocket endpoint for subscriptions")
async def websocket_endpoint(websocket: WebSocket):
    limit_websocket(websocket)
    client = None
    try:
        client = ledger.events.add_client(websocket, ledger.db, ledger.crud)
    except Exception as e:
        logger.debug(f"Exception: {e}")
        await asyncio.wait_for(websocket.close(), timeout=1)
        return

    try:
        # this will block until the session is closed
        await client.start()
    except WebSocketDisconnect as e:
        logger.debug(f"Websocket disconnected: {e}")
    except Exception as e:
        logger.debug(f"Exception: {e}")
    finally:
        if client and client in ledger.events.clients:
            ledger.events.remove_client(client)
        if websocket.client_state.name != "DISCONNECTED":
            await asyncio.wait_for(websocket.close(), timeout=1)


@router.post(
    "/v1/mint/bolt11",
    name="Mint tokens with a Lightning payment",
    summary="Mint tokens by paying a bolt11 Lightning invoice.",
    response_model=PostMintResponse,
    response_description=(
        "A list of blinded signatures that can be used to create proofs."
    ),
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
@redis.cache()
async def mint(
    request: Request,
    payload: PostMintRequest,
) -> PostMintResponse:
    """
    Requests the minting of tokens belonging to a paid payment request.

    Call this endpoint after `POST /v1/mint/quote`.
    """
    logger.trace(f"> POST /v1/mint/bolt11: {payload}")

    promises = await ledger.mint(
        outputs=payload.outputs, quote_id=payload.quote, signature=payload.signature
    )
    blinded_signatures = PostMintResponse(signatures=promises)
    logger.trace(f"< POST /v1/mint/bolt11: {blinded_signatures}")
    return blinded_signatures


@router.post(
    "/v1/melt/quote/bolt11",
    summary="Request a quote for melting tokens",
    response_model=PostMeltQuoteResponse,
    response_description="Melt tokens for a payment on a supported payment method.",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def melt_quote(
    request: Request, payload: PostMeltQuoteRequest
) -> PostMeltQuoteResponse:
    """
    Request a quote for melting tokens.
    """
    logger.trace(f"> POST /v1/melt/quote/bolt11: {payload}")
    quote = await ledger.melt_quote(payload)  # TODO
    logger.trace(f"< POST /v1/melt/quote/bolt11: {quote}")
    return quote


@router.get(
    "/v1/melt/quote/bolt11/{quote}",
    summary="Get melt quote",
    response_model=PostMeltQuoteResponse,
    response_description="Get an existing melt quote to check its status.",
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
async def get_melt_quote(request: Request, quote: str) -> PostMeltQuoteResponse:
    """
    Get melt quote state.
    """
    logger.trace(f"> GET /v1/melt/quote/bolt11/{quote}")
    melt_quote = await ledger.get_melt_quote(quote)
    resp = PostMeltQuoteResponse(
        quote=melt_quote.quote,
        amount=melt_quote.amount,
        unit=melt_quote.unit,
        method=melt_quote.method,
        request=melt_quote.request,
        fee_reserve=melt_quote.fee_reserve,
        state=melt_quote.state.value,
        expiry=melt_quote.expiry,
        payment_preimage=melt_quote.payment_preimage,
        change=melt_quote.change,
    )
    logger.trace(f"< GET /v1/melt/quote/bolt11/{quote}")
    return resp


@router.post(
    "/v1/melt/bolt11",
    name="Melt tokens",
    summary=(
        "Melt tokens for a Bitcoin payment that the mint will make for the user in"
        " exchange"
    ),
    response_model=PostMeltQuoteResponse,
    response_description=(
        "The state of the payment, a preimage as proof of payment, and a list of"
        " promises for change."
    ),
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
@redis.cache()
async def melt(request: Request, payload: PostMeltRequest) -> PostMeltQuoteResponse:
    """
    Requests tokens to be destroyed and sent out via Lightning.
    """
    logger.trace(f"> POST /v1/melt/bolt11: {payload}")
    if payload.prefer_async:
        resp = await ledger.async_melt(
            proofs=payload.inputs, quote=payload.quote, outputs=payload.outputs
        )
    else:
        resp = await ledger.melt(
            proofs=payload.inputs, quote=payload.quote, outputs=payload.outputs
        )
    logger.trace(f"< POST /v1/melt/bolt11: {resp}")
    return resp


@router.post(
    "/v1/swap",
    name="Swap tokens",
    summary="Swap inputs for outputs of the same value",
    response_model=PostSwapResponse,
    response_description=(
        "An array of blinded signatures that can be used to create proofs."
    ),
)
@limiter.limit(f"{settings.mint_transaction_rate_limit_per_minute}/minute")
@redis.cache()
async def swap(
    request: Request,
    payload: PostSwapRequest,
) -> PostSwapResponse:
    """
    Requests a set of Proofs to be swapped for another set of BlindSignatures.

    This endpoint can be used by Alice to swap a set of proofs before making a payment to Carol.
    It can then used by Carol to redeem the tokens for new proofs.
    """
    logger.trace(f"> POST /v1/swap: {payload}")
    assert payload.outputs, Exception("no outputs provided.")

    signatures = await ledger.swap(proofs=payload.inputs, outputs=payload.outputs)

    return PostSwapResponse(signatures=signatures)


@router.post(
    "/v1/checkstate",
    name="Check proof state",
    summary="Check whether a proof is spent already or is pending in a transaction",
    response_model=PostCheckStateResponse,
    response_description=(
        "Two lists of booleans indicating whether the provided proofs "
        "are spendable or pending in a transaction respectively."
    ),
)
async def check_state(
    payload: PostCheckStateRequest,
) -> PostCheckStateResponse:
    """Check whether a secret has been spent already or not."""
    logger.trace(f"> POST /v1/checkstate: {payload}")
    proof_states = await ledger.db_read.get_proofs_states(payload.Ys)
    return PostCheckStateResponse(states=proof_states)


@router.post(
    "/v1/restore",
    name="Restore",
    summary="Restores blind signature for a set of outputs.",
    response_model=PostRestoreResponse,
    response_description=(
        "Two lists with the first being the list of the provided outputs that "
        "have an associated blinded signature which is given in the second list."
    ),
)
async def restore(payload: PostRestoreRequest) -> PostRestoreResponse:
    assert payload.outputs, Exception("no outputs provided.")
    outputs, signatures = await ledger.restore(payload.outputs)
    return PostRestoreResponse(outputs=outputs, signatures=signatures)
