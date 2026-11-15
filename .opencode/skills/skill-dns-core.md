# DNS-SHIELD CONTEXT & FILE OPTIMIZATION
This is a DNS filtering and proxy project. You operate with a strict context limit.
1. NEVER read domain blocklists, zone files, or raw DNS query logs in their entirety (e.g., `.txt`, `.csv`, `.zone`, `.log`, `hosts` files). These contain thousands of lines and will instantly overflow your memory buffer.
2. If you need to debug blocklist parsing or packet handling, read ONLY the specific parser functions using chunked reads.
3. Focus code inspection strictly on source files handling UDP/TCP sockets, DNS packet marshaling/unmarshaling, concurrency, and caching mechanics.
4. Completely ignore generated binaries, `vendor/` or `node_modules/` directories, and large test datasets.
