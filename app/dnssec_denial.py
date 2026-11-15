# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Authenticated denial of existence: checking NSEC (RFC 4035 section 5.4)
and NSEC3 (RFC 5155 section 8) proofs.

The records handed to `Denial` must already have had their signatures
verified with the keys of `zone`; this module only checks that what they
say actually proves the negative answer.

Every check returns SECURE (proven), INSECURE (the proof is valid but only
shows an opt-out delegation, or the zone uses more NSEC3 iterations than
we're willing to compute, RFC 9276) or BOGUS (no valid proof)."""

from __future__ import annotations

import base64

import dns.dnssec
import dns.name
import dns.rdatatype

SECURE = "secure"
INSECURE = "insecure"
BOGUS = "bogus"

# RFC 9276 section 3.2: validators may treat zones with more iterations as
# insecure. 150 is what BIND and Unbound use.
MAX_NSEC3_ITERATIONS = 150

_NS = dns.rdatatype.NS
_SOA = dns.rdatatype.SOA
_DS = dns.rdatatype.DS
_CNAME = dns.rdatatype.CNAME
_DNAME = dns.rdatatype.DNAME
_WILD = b"*"


def _types(rdata) -> frozenset[int]:
    types = set()
    for window, bitmap in rdata.windows:
        for index, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    types.add(window * 256 + index * 8 + bit)
    return frozenset(types)


def _wildcard(name: dns.name.Name) -> dns.name.Name:
    return dns.name.Name((_WILD,) + name.labels)


def _common(a: dns.name.Name, b: dns.name.Name) -> dns.name.Name:
    return a.split(a.fullcompare(b)[2])[1]


def _is_cut(types) -> bool:
    """The owner is a delegation (as seen from the parent) or a DNAME: names
    below it belong elsewhere, so the record says nothing about them."""
    return (_NS in types and _SOA not in types) or _DNAME in types


def _nodata_types_ok(types, rdtype) -> bool:
    if rdtype in types or _CNAME in types:
        return False
    if rdtype == _DS:
        # A DS denial must come from the parent side, not the child apex.
        return _SOA not in types
    # The parent side of a delegation can't deny the child's data.
    return not (_NS in types and _SOA not in types)


def _ancestors(name: dns.name.Name, zone: dns.name.Name):
    """name, name.parent(), ... down to and including zone."""
    while True:
        yield name
        if name == zone or name == dns.name.root:
            return
        name = name.parent()


class Denial:
    def __init__(self, zone: dns.name.Name, nsec=(), nsec3=()):
        """`nsec` / `nsec3`: verified RRsets of that type from `zone`."""
        self.zone = zone
        self._nsec = [
            (rrset.name, rdata.next, _types(rdata))
            for rrset in nsec
            if rrset.name.is_subdomain(zone)
            for rdata in rrset
        ]
        self._nsec3 = []
        self._nsec3_unusable = False
        for rrset in nsec3:
            if rrset.name.parent() != zone:
                continue
            owner_hash = rrset.name.labels[0].decode("ascii").upper()
            for rdata in rrset:
                if rdata.algorithm != 1 or rdata.iterations > MAX_NSEC3_ITERATIONS:
                    self._nsec3_unusable = True
                    continue
                params = (rdata.algorithm, rdata.iterations, bytes(rdata.salt))
                next_hash = base64.b32hexencode(rdata.next).decode("ascii")
                self._nsec3.append((params, owner_hash, next_hash, bool(rdata.flags & 1), _types(rdata)))
        self._hashes: dict[tuple, str] = {}

    # ------------------------------------------------------------ NSEC

    def _nsec_covering(self, name):
        """The NSEC record proving that `name` doesn't exist, as (owner, next)."""
        for owner, nxt, types in self._nsec:
            if owner == name:
                continue
            if owner < nxt:
                between = owner < name < nxt
            else:  # the last NSEC in the zone wraps round to the apex
                between = name > owner or name < nxt
            if not between:
                continue
            if nxt.is_subdomain(name):
                continue  # name is an empty non-terminal, so it does exist
            if name.is_subdomain(owner) and _is_cut(types):
                continue
            return owner, nxt
        return None

    def _nsec_matching(self, name):
        for owner, _, types in self._nsec:
            if owner == name:
                return types
        return None

    def _nsec_closest_encloser(self, name, owner, nxt):
        ce = max(_common(name, owner), _common(name, nxt), key=lambda n: len(n.labels))
        return ce if ce.is_subdomain(self.zone) else self.zone

    def _nsec_nxdomain(self, name) -> bool:
        cover = self._nsec_covering(name)
        if cover is None:
            return False
        ce = self._nsec_closest_encloser(name, *cover)
        return self._nsec_covering(_wildcard(ce)) is not None

    def _nsec_nodata(self, name, rdtype) -> bool:
        types = self._nsec_matching(name)
        if types is not None:
            return _nodata_types_ok(types, rdtype)
        # An empty non-terminal: an NSEC whose next name is below `name`.
        for owner, nxt, _ in self._nsec:
            if owner < name < nxt and nxt.is_subdomain(name) and nxt != name:
                return True
        # Wildcard NODATA: name doesn't exist, the wildcard does but lacks the type.
        if rdtype == _DS:
            return False
        cover = self._nsec_covering(name)
        if cover is None:
            return False
        types = self._nsec_matching(_wildcard(self._nsec_closest_encloser(name, *cover)))
        return types is not None and _nodata_types_ok(types, rdtype)

    def _nsec_wildcard(self, name, source) -> bool:
        cover = self._nsec_covering(name)
        return cover is not None and self._nsec_closest_encloser(name, *cover) == source

    # ------------------------------------------------------------ NSEC3

    def _hash(self, name, params) -> str:
        key = (name, params)
        value = self._hashes.get(key)
        if value is None:
            algorithm, iterations, salt = params
            value = dns.dnssec.nsec3_hash(name, salt, iterations, algorithm)
            self._hashes[key] = value
        return value

    def _nsec3_matching(self, name):
        for params, owner_hash, _, _, types in self._nsec3:
            if self._hash(name, params) == owner_hash:
                return types
        return None

    def _nsec3_covering(self, name):
        """The opt-out flag of the NSEC3 covering `name`, or None if none does."""
        for params, owner_hash, next_hash, optout, _ in self._nsec3:
            digest = self._hash(name, params)
            if owner_hash < next_hash:
                between = owner_hash < digest < next_hash
            else:
                between = digest > owner_hash or digest < next_hash
            if between:
                return optout
        return None

    def _nsec3_closest_encloser(self, name):
        """(closest encloser, opt-out flag of the record covering the next
        closer name), or None without a valid closest encloser proof."""
        next_closer = None
        for candidate in _ancestors(name, self.zone):
            types = self._nsec3_matching(candidate)
            if types is not None:
                if next_closer is None:
                    return None  # name itself exists
                if _is_cut(types):
                    return None
                optout = self._nsec3_covering(next_closer)
                return None if optout is None else (candidate, optout)
            next_closer = candidate
        return None

    def _nsec3_nxdomain(self, name) -> bool:
        proof = self._nsec3_closest_encloser(name)
        return proof is not None and self._nsec3_covering(_wildcard(proof[0])) is not None

    def _nsec3_nodata(self, name, rdtype) -> str:
        types = self._nsec3_matching(name)
        if types is not None:
            return SECURE if _nodata_types_ok(types, rdtype) else BOGUS
        proof = self._nsec3_closest_encloser(name)
        if proof is None:
            return BOGUS
        ce, optout = proof
        if rdtype == _DS:
            # No NSEC3 for the name: only an opt-out span can explain that,
            # and it means the delegation is unsigned.
            return INSECURE if optout else BOGUS
        types = self._nsec3_matching(_wildcard(ce))
        return SECURE if types is not None and _nodata_types_ok(types, rdtype) else BOGUS

    def _nsec3_wildcard(self, name, source) -> bool:
        if len(name.labels) <= len(source.labels):
            return False
        next_closer = name.split(len(source.labels) + 1)[1]
        return self._nsec3_covering(next_closer) is not None

    # ------------------------------------------------------------ checks

    def _result(self, nsec_ok: bool, nsec3_state: str) -> str:
        if nsec_ok:
            return SECURE
        if nsec3_state != BOGUS:
            return nsec3_state
        if self._nsec3_unusable and not self._nsec:
            return INSECURE
        return BOGUS

    def nxdomain(self, name: dns.name.Name) -> str:
        """`name` doesn't exist and no wildcard could have produced it."""
        if not name.is_subdomain(self.zone):
            return BOGUS
        return self._result(self._nsec_nxdomain(name), SECURE if self._nsec3_nxdomain(name) else BOGUS)

    def nodata(self, name: dns.name.Name, rdtype: int) -> str:
        """`name` exists (or matches a wildcard) but has no `rdtype` data."""
        if not name.is_subdomain(self.zone):
            return BOGUS
        return self._result(self._nsec_nodata(name, rdtype), self._nsec3_nodata(name, rdtype))

    def wildcard(self, name: dns.name.Name, source: dns.name.Name) -> str:
        """An answer for `name` synthesised from the wildcard `*.source`:
        `name` itself must not exist and nothing closer may either."""
        if not name.is_subdomain(source) or not source.is_subdomain(self.zone):
            return BOGUS
        return self._result(self._nsec_wildcard(name, source), SECURE if self._nsec3_wildcard(name, source) else BOGUS)
