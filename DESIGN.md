# mtx-gate — draft v0 (2026-10-27, retroid-15)

A gate in front of MediaMTX at stream.d3adb5.ca. Nobody reaches a stream unless a client the gate trusts let them in,
from one IP address, for a limited time. This sits on top of E2E encryption (webcam) and DTLS-SRTP/TLS (Teevee), and
doesn't replace either.

## What the user asked for

- Every read needs a login: no anonymous read, not even on unguessable `mcam/` paths.
- A proxy in front of MediaMTX that the clients negotiate with, so it opens viewer IPs only for a while.
- The same gate for Teevee shares.
- No stream can leak to anyone, on top of E2E encryption.

## Shape

The gate runs as a sidecar in the MediaMTX pod (Go, one static binary, `ghcr.io/d3adb5/mtx-gate`). Its state lives in
memory only: when it restarts, every share and ticket is gone, and clients register again.

```
internet ─ TCP 8322 ─▶ gate L4 proxy ──PROXY v2──▶ MediaMTX RTSPS 127.0.0.1:18322   (rtspTrustedProxies: 127.0.0.1)
         ─ HTTPS ─▶ Traefik ─┬─ /gate/v1/*  ─▶ gate API
                             └─ WHIP/WHEP ─forwardAuth(gate)─▶ MediaMTX webrtc     (webrtcTrustedProxies: Traefik)
MediaMTX authMethod: http ─▶ gate 127.0.0.1:9000/auth   (every publish, read, api and metrics action)
```

Each connection has to pass three checks, and each check works on its own:

1. **IP gate (network).** The 8322 proxy accepts TCP only from IPs that are open right now. Any other IP gets a reset
   before TLS, so a scanner never sees a certificate or an RTSP banner. On WHIP/WHEP, Traefik forwardAuth returns
   404 for IPs that aren't open.
2. **Credential (MediaMTX http auth).** The gate decides with the real IP (from the PROXY header or X-Forwarded-For),
   the user and password, the action and the path. It answers 401 unless the credential is valid for that exact
   path, action and IP.
3. **Payload.** Webcam frames are E2E (aes256gcm-nal-v1). Teevee is protected by transport encryption only.

If the gate is down, MediaMTX refuses everything (fail closed). The gate never logs paths, tickets, logins or IPs.
It counts allow/deny decisions in metrics only.

## Principals

- **Owners**: beaver and eevee. They are the only publishers. Their logins move from MediaMTX's internal users into the
  gate, as bcrypt hashes from the sealed secret.
- **Tickets**: one per viewer, issued by the sender. Each ticket is bound to one path, the read action, the owner
  login that redeemed it, and one IP at a time. **Watching takes both** (user decision 2026-10-27): the viewer's own
  owner login and a ticket from the sender. A guest without a relay account can't watch.

## API (HTTPS, behind Traefik's rate limit; JSON)

| call | auth | effect |
| --- | --- | --- |
| `POST /gate/v1/open` | owner Basic | Opens the caller's IP for 120 s. The client renews every 60 s while it publishes or watches. A live proxied connection also keeps the IP open, plus a 60 s grace after it ends. |
| `PUT /gate/v1/shares/{path}` | owner Basic | Claims `mcam/<32 hex>` (or the owner's fixed Teevee path) for this owner, with a TTL of 90 s. The sender renews it every 30 s. Only the claiming owner may publish there. |
| `DELETE /gate/v1/shares/{path}` | owner Basic | Ends the share: drops its tickets, kicks every reader and the publisher, and closes the IPs those tickets opened. |
| `POST /gate/v1/shares/{path}/tickets` | owner Basic | Returns `{id, secret, redeem_by}`. The viewer has 60 s to redeem the ticket. |
| `DELETE /gate/v1/shares/{path}/tickets/{id}` | owner Basic | Revokes one viewer: kicks their MediaMTX sessions (`/v3/*/kick`, over localhost) and closes their IP unless something else holds it open. |
| `POST /gate/v1/redeem` | owner Basic + `{id, secret}` | Binds the ticket to the caller's IP and opens that IP for 120 s (the viewer renews it the same way). A second redeem from another IP moves the binding (phone switching from Wi-Fi to LTE) and kicks the old IP. |

**Viewer credentials at MediaMTX:** the viewer's own owner login. The gate accepts a read only if a ticket for that
path was redeemed by that same login and is bound to the connecting IP. The ticket secret is sent only to the gate.

**Owner logins at MediaMTX:** they publish only to paths they hold a share on (Teevee's fixed paths count as held
while the owner has them open). Reading other owners' fixed Teevee paths stays allowed (the current behaviour), but
only from an open IP.

## Webcam protocol change (v1 → v1.1, box-only)

- The grant/rekey box gains `gate: {url, id, secret}`. The viewer redeems the ticket with its own relay login, then
  connects to RTSPS with that same login. Viewers that predate this ignore `gate` and the relay refuses them; that's
  acceptable.
- Sender: `PUT share` at start and every 30 s, a ticket per grant, `DELETE` the ticket on revoke, `DELETE` the share
  on stop. On a revoke that moves the path, the remaining viewers get new tickets on the new path.
- The relay can now revoke a viewer by itself; the key rotation stays as well.
- The sender's own publish connection: `POST open` before ANNOUNCE.

## Teevee

Teevee has no side channel between the sharer and a watcher, so it keeps the owner logins. Watchers and publishers
call `POST /gate/v1/open` with their login before WHIP/WHEP and renew it while connected. Optionally, an owner could
mint tickets for a guest later (a share link); that's not part of v0.

## Residual risk (stated, not fixed)

- **WebRTC ICE UDP 8189** stays open to everyone. MediaMTX answers STUN only for sessions created after an authorised
  WHEP/WHIP exchange (ufrag/pwd), and the media is DTLS-SRTP. A UDP proxy that filters by IP would break MediaMTX's
  view of the peer address.
- **Same NAT.** Anyone behind the same public IP as a viewer gets past check 1. They still need the viewer's login
  and a ticket redeemed under it for check 2.
- **The MediaMTX/cluster admin** can still see metadata (which shares are live, their timing and bitrate), and so can
  the gate. That's unchanged from the webcam spec.

## Rollout

1. Done (secretlab 25eb481, not pushed): no `anonymous` read on `mcam/`. Viewers use their own owner login from now
   on, so Mumble and Mumla read with the relay login fields they already use for sharing, and ask for a login before
   watching when none is set.
2. Gate + chart support (an `extraContainers` sidecar, an `auth.http` mode, trusted proxies). Tested against the
   local test relay built from ~/projects/mediamtx.
3. Mumble and Mumla v1.1 grants; Teevee `open` calls.
4. Production: the user pushes secretlab, the charts and the gate image.
