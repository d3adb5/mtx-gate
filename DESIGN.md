# mtx-gate — v0.1 (2026-10-27, retroid-15; reviewed by Mumla, mumble-54, teevee-81)

A gate in front of MediaMTX at stream.d3adb5.ca. Nobody reaches a stream unless a client the gate trusts let them in,
from one IP address, for a limited time. This sits on top of E2E encryption (webcam) and DTLS-SRTP/TLS (Teevee), and
doesn't replace either.

## What the user asked for (2026-10-27)

- Every read needs a login: no anonymous read, not even on unguessable `mcam/` paths.
- A proxy in front of MediaMTX that the clients negotiate with, so it opens viewer IPs only for a while.
- The same gate for Teevee shares.
- No stream can leak to anyone, on top of E2E encryption.
- **Watching a webcam share takes both** the viewer's own relay (owner) login and a ticket from the sender. A guest
  without a relay account can't watch.

## Shape

The gate runs as a sidecar in the MediaMTX pod (Go, standard library only, `ghcr.io/d3adb5/mtx-gate`). Its state lives
in memory only (see "Gate restart").

```
internet ─ TCP 8322 ─▶ gate L4 proxy ──PROXY v2──▶ MediaMTX RTSPS 127.0.0.1:18322   (rtspTrustedProxies: 127.0.0.1)
         ─ HTTPS ─▶ Traefik ─┬─ /gate/v1/*  ─▶ gate API :9080   (own rate-limit bucket)
                             └─ WHIP/WHEP ─forwardAuth(gate :9080/forward)─▶ MediaMTX webrtc
MediaMTX authMethod: http ─▶ gate 127.0.0.1:9000/auth   (publish, read, api, metrics; everything else refused)
```

Each connection has to pass three checks, and each check works on its own:

1. **IP gate (network).** The 8322 proxy accepts TCP only from IPs that are open right now. Any other IP gets a reset
   before TLS, so a scanner never sees a certificate or an RTSP banner. On WHIP/WHEP, Traefik forwardAuth returns
   404 for IPs that aren't open.
2. **Credential (MediaMTX http auth).** The gate decides with the real IP (from the PROXY header or
   X-Forwarded-For), the login, the action and the path.
3. **Payload.** Webcam frames are E2E (aes256gcm-nal-v1). Teevee is protected by transport encryption only.

If the gate is down, MediaMTX refuses everything (fail closed). The gate logs no paths, tickets, logins or IPs. It
only counts decisions (`GET /stats` on the loopback auth port).

**Permissive mode** (the default; `-enforce` turns enforcing on): MediaMTX publish/read and the IP gate allow
everything, and only count what they would have refused (`would_deny`). The api/metrics actions are always enforced.
Production runs permissive until the old clients are gone (see Rollout).

## Opens (IP leases)

- An open IP key is an IPv4 address, or an IPv6 /64 (privacy addresses rotate within it). stream.d3adb5.ca has no
  AAAA record today. A client that may use both address families calls `open` over each of them. Each family is its
  own lease.
- A lease lasts 120 s from the last `open`, `redeem` or share `PUT`. Clients renew every 60 s, so at least 60 s of
  grace is left after the last renewal (for a WHIP/WHEP DELETE on stop, for example).
- A live proxied 8322 connection also holds its IP open, plus 60 s after it closes. Renewing is optional while
  connected over RTSPS. **WebRTC clients have only renewals:** their media goes to UDP 8189, which the gate never
  sees.
- **A lapsed lease never kicks an existing session.** It only stops new ones. Sessions end on a revoke, when a share
  ends, or by themselves.
- `open`, `redeem` and `PUT share` answer `{"ip": <address the gate saw>, "ttl_s": ...}`. The client can pin its
  RTSPS/WHEP socket to that address family, and log a mismatch as the reason for a refusal.

## API (HTTPS at `https://<the client's own relay host>/gate/v1`, JSON)

Owner Basic = the caller's own relay login. A client sends it **only to its own configured relay host** (https,
certificate validated). It never sends it to a URL taken from a grant or any other peer message.

| call | auth | answers |
| --- | --- | --- |
| `POST /open` | owner Basic | 200 `{ip, ttl_s}`: opens the caller's IP. |
| `PUT /shares/mcam/<32 hex>` | owner Basic | **201** when the gate creates the share (first claim, or after a restart or expiry: mint fresh tickets), **200** on a renewal. Both return `{ip, ttl_s: 90}` and also open the caller's IP. 403 if another owner holds the path. Renew every 30 s. While the publisher's RTSPS connection is up, the share stays held even if renewals are missed. |
| `DELETE /shares/<path>` | owner Basic | 204. Drops the tickets and kicks every session on the path. |
| `POST /shares/<path>/tickets` | owner Basic | 200 `{id, secret, redeem_in_s: 60}`. Up to 32 per share. |
| `DELETE /shares/<path>/tickets/<id>` | owner Basic | 204. Kicks the sessions that ticket's login has on the path. |
| `POST /redeem` body `{id, secret}` | owner Basic | 200 `{ip, ttl_s}`. Binds the ticket to (login, IP) and opens the IP. `redeem_in_s` bounds only the **first** redeem. After that the ticket is good for the share's whole life, and redeeming again is idempotent from the same IP. From a new IP it moves the binding and kicks the old IP's sessions on that path. One login may hold several tickets (desktop + phone on one account). |

Status codes clients act on: **401** bad owner login (ask the user; the answer is the same for an unknown user and a
wrong password), **403** path or ticket belongs to another login, **404** unknown share or ticket (the gate
restarted, the share ended, or the ticket was revoked), **410** the first-redeem window is over (send a new
watch-request), **429** limit reached. Every refusal the gate makes itself carries the header `X-Mtx-Gate: 1` and an
empty body. MediaMTX's own 404 has a JSON body and no such header.

At MediaMTX, a 401 can mean a credential problem or a missing (login, IP) binding: http auth can't say more. A
client that gets a 401 right after a successful redeem compares the `ip` it was given, then calls `open`. If `open`
answers 401, the login is wrong. A read on a valid ticket before the publisher is up gets MediaMTX's 404
(retry); the gate passes auth for it.

## Webcam protocol v1.1 (box-only)

- The grant **and rekey** boxes gain `gate: {id, secret}`, with no URL. The viewer derives the gate from its own
  relay setting.
- Viewer: redeem, then RTSPS with its own login, but only to the relay host it is configured for. A grant naming
  another relay without its own credential ends the view. Mumla 1c6039e and Mumble 4cc882209 already do this for
  the RTSPS login.
- Sender: `PUT share` at share start (before the camera opens; that also opens its IP), and every 30 s. One ticket
  per grant. `DELETE ticket` on a revoke. `DELETE share` on stop. A revoke that moves the path PUTs the new path,
  then sends each remaining viewer a rekey with `urls` and a new `gate` ticket.
- **The renewal answers 201** (the gate forgot the share): the sender mints a ticket for every current viewer and
  sends each one a rekey with `gate` and no `urls`. The viewer redeems again when it receives it.
- **410 on redeem:** the viewer sends watch-request again, by itself.
- The relay can now revoke a viewer by itself; the key rotation stays as well.

## Teevee

Teevee has no side channel between the sharer and a watcher, so it keeps the owner logins. Every client calls
`open` **right before every WHIP/WHEP POST**, from the same process. Teevee does this in `Signalling.exchange`,
which covers start, restart, codec change and rebuild. Clients renew every 60 s while connected, and keep renewing
until the stop DELETE has gone out. A 404 carrying `X-Mtx-Gate` means the IP isn't open; it never means "not
streaming". Owners publish to their own fixed paths and read each other's, from an open IP.

**Browser watching: user decision pending.** A browser can't call `open`. Either browser watching on MediaMTX's page
ends, or the gate serves `/gate/v1/watch/<path>`: the browser's Basic login prompt, then `open`, then MediaMTX's
reader in a frame, with a fetch renewal every 60 s.

Later: owner-minted guest tickets (share links) would add a ticket-only read principal. Redeem keeps owner Basic as a
check, not a structural part of tickets, so this doesn't need a v2.

## Gate restart

The gate's state is memory only, by choice: nothing to leak at rest. On a restart:
- RTSPS viewers and publishers are cut (the proxy lives in the gate process). This is a known cost; restarts are
  rare (deploys).
- Senders' next renewal gets 201 and they re-issue tickets (above); Teevee clients' next `open` restores their IP.
- WebRTC sessions continue (media bypasses the gate).

## Rate limits

`/gate/v1` gets its own Traefik bucket, separate from WHIP/WHEP and generous: a network handover from one device is
open + redeem + PUT + reconnect, and two devices can sit behind one home NAT. Suggested: 120/min, burst 60 per
source. Failed logins cost the caller 1 s.

## Residual risk (stated, not fixed)

- **WebRTC ICE UDP 8189** stays open to everyone. MediaMTX answers STUN only for sessions created after an authorised
  WHEP/WHIP exchange (ufrag/pwd), and the media is DTLS-SRTP.
- **Same NAT.** Anyone behind the same public IP as a viewer gets past check 1. They still need the viewer's login
  and a ticket redeemed under it for check 2.
- **The cluster admin** can still see metadata (which shares are live, their timing and bitrate), and so can the
  gate. That's unchanged from the webcam spec.
- MediaMTX `expireAt` (http-auth response) isn't used: cutting sessions at lease end contradicts "a lapse never
  kicks". Kicks happen through the API (`/v3/{rtsps,webrtc}/sessions/kick/{id}`, found by path, user and IP in
  `.../list`), as the internal user `mtx-gate`, from loopback only, with a random password per start.

## Rollout

1. Done: no anonymous read on `mcam/` (secretlab 25eb481, not pushed). Viewers use their own relay login (Mumla
   1c6039e, Mumble 4cc882209/ddf38bd77). The local test relay still has `any` read; it needs mirroring (the user
   starts it).
2. Gate (this repo) + chart: an `extraContainers` sidecar, `authMethod: http`, `rtspsAddress: 127.0.0.1:18322`,
   `rtspTrustedProxies`, `webrtcTrustedProxies`, the Service's 8322 targeting the gate, the forwardAuth middleware,
   and the `/gate/v1` Ingress. Tested against a local relay.
3. Clients: Mumble and Mumla v1.1, Teevee `open` calls, teevee-desktop 0.4.0.
4. Deploy permissive. The user pushes secretlab, the charts and the gate image.
5. **Before enforcing:** teevee-desktop 0.4.0 installed on eevee's machine, Teevee updated on every phone, and
   `would_deny` stays at 0 through a share and a watch on each client.
6. `-enforce`.
