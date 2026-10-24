# SAFETY: running SSRD on the local box

This replaces the VPS plan. Everything runs on one local Linux workstation (`box`) with an encrypted disk and Docker, on a home or shared residential network.
That cuts the cost to $0, but scam sites now get fetched from a machine you use every day, on your home network. This file explains how that risk is contained.
**Live fetching was turned on 2026-10-17 at Rahil's direction**, after `ssrd safety-check` passed inside the container. The mode is `passive_visit`, at 20 requests/min with 2 parallel workers.

## What changes vs. a VPS

| Concern | VPS plan | Local box | Control |
|---|---|---|---|
| Scam content near personal files | Isolated machine | Same machine | Fetcher runs in a hardened container (below). Only `data/` is mounted. No browser, no JS. |
| Reaching your LAN, tailnet or Docker services (SSRF / DNS rebinding) | Nothing nearby | Your private LAN ranges (RFC 1918), Tailscale 100.64/10, many Docker bridges 172.16/12 | Two independent layers: (1) the app resolves DNS itself and refuses any non-global IP on every hop, connecting only to that pinned IP; (2) a firewall inside the container drops all egress to private, CGNAT, link-local and loopback ranges. |
| Whose IP the sites see | A datacenter IP | Your residential or shared-building public IP | Few requests per minute, one fixed browser UA, no forms. On a shared NAT you are not individually identifiable; check whether yours is. You see less cloaking than from a datacenter, which **changes the decoy share**. Write that up as a method note. |
| ISP or building network | Provider AUP | Your ISP's or building's acceptable-use policy | Low volume, HTTP(S) only, never port-scan. If you get a notice: stop, reply, don't evade. |
| Running from the wrong network | n/a | The laptop might join a campus or employer network | **Egress check:** the fetcher refuses to start unless the current public IP's ASN is on `safety.allowed_egress_asns` (default: empty, so the fetcher refuses to start until you list your home network's ASN in the git-ignored `config/ssrd.local.toml`). This keeps it off campus or employer networks, where their acceptable-use policy applies. |
| Uptime | 24/7 | Box sleeps or restarts | Restart policies. Ingest resumes from the saved tile position. Gaps are logged, and time-to-flag counts only uptime. |
| Bandwidth | VPS cap | Home Wi-Fi | No certstream-server-go. A Python **names-tile tailer** reads only the small JSONL "names" tiles from Let's Encrypt (Sycamore and Willow) and Geomys (Tuscolo). Measured about 25 entries/s per LE log (Oct 17), roughly 0.3 KB per entry, so a few GB/day at most. The daily total is logged. |

## Container hardening (fetcher)

- `python:3.12-slim` base, non-root UID 10001, read-only root filesystem, `tmpfs /tmp` (noexec).
- `cap_drop: ALL`. The entrypoint gets `NET_ADMIN` only to install the egress firewall in **its own** network namespace, then drops it through `setpriv` before Python starts.
- `no-new-privileges`, memory 1 GB, 2 CPUs, 256 pids.
- Bind mounts: `./data` read-write. Nothing else from `$HOME`, no Docker socket.
- A dedicated Docker network. DNS goes to public resolvers (1.1.1.1 and 8.8.8.8), never the LAN router.

Egress firewall (nftables, inside the container, default drop):
- Allowed: TCP 80/443 to global addresses; UDP/TCP 53 to the configured resolvers only.
- Dropped: 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, 127/8, 0/8, 224/4, 240/4, ::1, fc00::/7, fe80::/10 and everything else.

## Fetch rules (enforced in code, tested)

1. **Mode.** `passive_visit` (chosen 2026-10-17) is the homepage GET, plus the favicon and up to 5 same-origin non-library JS/CSS files, **only when the homepage already looks like an investment site** (≥ 3 investment terms). `strict` is homepage only.
2. GET only, no cookies kept, no JS, no forms, never a URL with a query string we invented.
3. Timeouts: 5 s connect, 10 s per read, and a **20 s hard cap per response body** (guards against slow-drip tarpits). ≤ 3 redirects, http/https only, and the IP guard runs again on every hop.
4. Bodies are streamed and aborted at 2 MB. Content-Type allowlist. Binaries are never saved; only their hash and size are logged.
5. Images are never decoded. The favicon is hashed as raw bytes.
6. Rate: a global token bucket at 20 requests/min, 2 parallel network workers (database writes stay on one thread), and one visit per registrable domain per scheduled slot.
7. Blocked, cloaked or erroring sites are recorded, never retried from another IP. No proxies, no VPN hopping.
8. Kill switch: `fetch.enabled = false`, or `docker compose stop fetcher`.

## Handling captured content

- Raw bytes are stored gzip-compressed as `data/captures/<sha256>.gz`, mode 0600. Nothing is ever executed or opened in a browser.
- The review queue (`ssrd review`) shows **sanitized text**: scripts and styles stripped, URLs defanged (`hxxps://example[.]com`).
- `data/` (mode 700) is gitignored and sits on the LUKS-encrypted disk. `ssrd backup` writes gpg AES-256 archives to `~/ssrd-backups` (weekly timer); only those may be copied off the box. Keep `data/.backup_key` in a password manager too, or the backups cannot be restored. `data/.env` is never backed up.
- Crypto addresses and Telegram/WhatsApp handles are kept only as private linking evidence. Never interact with them.

## Third parties

- **urlscan:** the client has no scan-submission code path (a test enforces this). It only searches and fetches results, and caches them locally.
- **CBR, DFPI and the CT logs** are public read-only sources, used at polite rates.
- Flagged domains are never sent to any external service except the DNS lookup the fetch itself needs.

## Legal and people (unchanged from docs/research.md)

Passive observation only. Run it on your own initiative; don't take collection instructions from the VCU. Use "matches kit X" language. Never contact operators or victims. Findings go privately to the VCU through their official channel, only after you approve the text.

## Before turning on live fetching (checklist)

- [x] Read this file.
- [x] `ssrd safety-check` passes: egress ASN allowed, container firewall active, private-IP probes blocked, process has no capabilities (2026-10-17).
- [x] Mode: `passive_visit` (2026-10-17).
- [ ] Optional: a 30-minute check with an advisor or UMich OGC.
