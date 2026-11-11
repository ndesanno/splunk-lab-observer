# Bind one private LAN address behind HTTPS and an owner login

The owner views the lab from a Mac on the same network as the mini PC. An SSH tunnel would protect the existing loopback interface but would require a tunnel on each device; a direct HTTPS port matches the intended use. Explicit LAN mode binds one private IPv4 address, requires a certificate and separate owner login, and keeps those secrets outside the repository. Loopback mode remains the default.

The local certificate is self-signed for the mini PC's IP, so the owner must verify its fingerprint and trust it on the Mac. The server restricts cross-origin browser requests, keeps the observer session cookie out of Splunk requests, and does not configure internet or router exposure. This is a single-owner service for a trusted LAN.
