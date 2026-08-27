Why Plain HTTP Exposes Your Scale JWTs — and What TLS Actually Fixes

Right now, your Scale control server (main.go, Fiber, :8080) issues JWT tokens over POST /api/login and expects them back in the Authorization: Bearer <token> header on every subsequent request — /api/user, /api/devices/register, /api/devices/heartbeat, /api/poll. If this traffic isn't wrapped in TLS, that header travels across the network in plaintext, readable by anyone positioned on the path.
What "Plaintext on the Wire" Actually Means

HTTP over plain TCP (no TLS) sends every byte — headers, body, everything — unencrypted. A JWT looks like this:

text
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.4f3a...

This string is not encrypted, only encoded (Base64). Encoding is not security — anyone can decode it instantly. If someone captures this packet with Wireshark or tcpdump on:

    A shared Wi-Fi network (coffee shop, hostel, office)

    A compromised router anywhere between client and your control server

    Your own cloud provider's internal network, if traffic isn't isolated

    A malicious VPN or proxy the client is unknowingly routed through

...they get the full JWT in one shot. No cracking required.
Why This Is Especially Dangerous for JWTs Specifically

A stolen password is bad, but a stolen valid JWT is worse in the short term — it's a live, already-authenticated session token. Your Scale server signs JWTs with HS256, and until that token's expiry, anyone holding it can:

text
Attacker captures JWT from network sniff
        │
        ▼
Replays it directly:
  GET /api/poll
  Authorization: Bearer <stolen JWT>
        │
        ▼
Server has NO way to distinguish attacker
from legitimate device — it only validates
the signature, not who's presenting it

Your control server's JWT middleware only checks: is this signature valid, and has it expired? It has no concept of "is this coming from the IP/device that originally logged in." So a sniffed token is a fully functional impersonation credential for its entire lifetime — the attacker can call /api/devices/heartbeat, /api/poll, and see your mesh's peer list, endpoints, and device data.
What TLS Specifically Changes Here

This connects directly to the handshake mechanics we covered earlier. Once your control server is behind properly configured HTTPS:

    Certificate validation must actually happen (not InsecureSkipVerify: true like your relay currently has) — the client verifies it's really talking to your control server, not an attacker who set up a fake server on the same network to intercept login requests.

    After the handshake, a symmetric session key encrypts everything — including the Authorization header. An eavesdropper now sees only ciphertext:

text
Without TLS:  Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
With TLS:     [encrypted blob — unreadable without session key]

    Integrity is also protected — TLS includes authentication tags (via AEAD ciphers like AES-GCM) so an attacker can't tamper with the request mid-flight without detection, not just read it.

The Critical Nuance: TLS Protects the Wire, Not the Token Itself

This is worth being precise about, because it's a common misconception. TLS encrypts the transport channel — the JWT itself is still exactly the same static bearer token before and after TLS is added. TLS doesn't make the JWT cryptographically "safer" in isolation; it just prevents anyone on the network path from reading it in transit.

That means these risks remain even with perfect TLS:

    If the JWT leaks via a client-side log, browser history, or the scale-client binary storing it insecurely on disk — TLS never touches that.

    If your server itself is compromised, TLS on the wire is irrelevant — the attacker already has the request before or after encryption boundaries.

    Replay within the token's validity window is still possible if someone gets the token through any means other than network sniffing (e.g., malware on the client's Pune-based machine reading its config file).

Concrete Fix Path for Scale

Given your architecture, here's what actually needs to change, layered from your Fiber server outward:

    Terminate TLS at the Fiber server directly, or put a reverse proxy (nginx, Caddy, or a cloud load balancer) in front of :8080 that terminates HTTPS and forwards to Fiber over localhost — the second approach is more common in production Go deployments.

    Never set InsecureSkipVerify: true on the control server's TLS config the way your relay currently does — that flag disables exactly the certificate-authenticity check that stops a MITM from injecting itself between client and server during login.

    Shorten JWT expiry so a sniffed token (via any leak vector, not just network) has a smaller window of usefulness — combined with a refresh-token pattern if you want longer sessions without long-lived bearer tokens.

    Consider binding JWTs to device public keys you already have in your devices table — since Scale already tracks public_key per device, you could add a check that ties token validity to the requesting device's known key material, making a bare stolen JWT less useful without also having the WireGuard private key.

Socratic Audit Questions

    Walk through precisely why encoding (Base64) is not encryption, and demonstrate in your own words why an attacker doesn't need any cryptographic effort to read a plaintext JWT off the wire.

    Your control server validates JWT signatures but not origin. Design, in words, a minimal check you could add to /api/poll that would make a sniffed-and-replayed JWT far less useful to an attacker, using data you already store in PostgreSQL or Redis.

    Explain the exact difference between what TLS protects and what it doesn't, using the three leak vectors listed above (client logs, server compromise, malware). Why would a security engineer say "TLS is necessary but not sufficient" for token security?

    If your relay's InsecureSkipVerify: true and control server both lack real certificate validation, describe the single MITM attack chain that would let an attacker capture a valid JWT and then use it against your control server's /api/devices/heartbeat endpoint to poison peer endpoint data for other users.

