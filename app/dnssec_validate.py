# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Local DNSSEC validation (dns.dnssec_validation: "local").

Instead of trusting the upstream's AD flag, DNS-shield checks the
signatures itself, from the root trust anchor down:

* every RRset in an answer that carries RRSIGs is verified with the
  signer zone's DNSKEYs;
* a zone's DNSKEYs are trusted when one of them matches a DS record that
  is itself signed by the parent zone's trusted keys (the root's DNSKEYs
  are checked against the built-in trust anchors, which
  dns.dnssec_trust_anchors can replace);
* an RRset without signatures is bogus if its zone is signed (that's
  what an attacker stripping signatures looks like), insecure otherwise;
* denials are proven (NSEC/NSEC3, see app.dnssec_denial): a zone counts as
  unsigned only when its signed parent proves there is no DS for it (or
  covers it with an NSEC3 opt-out span), and NXDOMAIN / NODATA answers and
  wildcard-synthesised answers from a signed zone need a valid proof.

If the chain can't be established at all (the root keys don't match the
anchors, the upstream returns no DNSSEC records), the result is
"indeterminate" and the answer is passed through as before rather than
failing every lookup."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from app.dnssec_denial import Denial

logger = logging.getLogger("dnsshield.dnssec")

SECURE = "secure"
INSECURE = "insecure"
BOGUS = "bogus"
INDETERMINATE = "indeterminate"

# IANA root zone KSKs (KSK-2017 and KSK-2024), as DS records, from
# https://data.iana.org/root-anchors/root-anchors.xml (the same values ship
# in Unbound's unbound-anchor and BIND's bind.keys).
ROOT_TRUST_ANCHORS = (
    ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
)

QueryFn = Callable[[dns.name.Name, int], dns.message.Message]


class _ChainError(Exception):
    """The chain of trust couldn't be checked (not the same as bogus)."""


def _parse_anchors(lines) -> dns.rrset.RRset:
    rrset = None
    for line in lines:
        parts = line.split()
        # "<owner> [IN] DS <key tag> <alg> <digest type> <digest>"
        owner = dns.name.from_text(parts[0])
        rest = parts[1:]
        if rest and rest[0].upper() == "IN":
            rest = rest[1:]
        if not rest or rest[0].upper() != "DS":
            raise ValueError(f"not a DS record: {line!r}")
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, " ".join(rest[1:]))
        if rrset is None:
            rrset = dns.rrset.RRset(owner, dns.rdataclass.IN, dns.rdatatype.DS)
        rrset.add(rdata)
    if rrset is None:
        raise ValueError("no trust anchors")
    return rrset


def _signatures(message: dns.message.Message, section, name, rdtype):
    for rrset in section:
        if rrset.name == name and rrset.rdtype == dns.rdatatype.RRSIG and rrset.covers == rdtype:
            return rrset
    return None


def _find(section, name, rdtype):
    for rrset in section:
        if rrset.name == name and rrset.rdtype == rdtype:
            return rrset
    return None


class LocalValidator:
    def __init__(self, query: QueryFn, anchors=ROOT_TRUST_ANCHORS, cache_seconds: float = 3600.0, now=time.time):
        self._query = query
        self._anchors = _parse_anchors(anchors)
        self._cache_seconds = cache_seconds
        self._now = now
        self._lock = threading.Lock()
        # zone -> (expires, state, DNSKEY rrset or None)
        self._zones: dict[dns.name.Name, tuple[float, str, dns.rrset.RRset | None]] = {}
        # owner name -> (expires, zone apex)
        self._apex: dict[dns.name.Name, tuple[float, dns.name.Name]] = {}

    # ------------------------------------------------------------ chain

    def _cached_zone(self, zone):
        with self._lock:
            entry = self._zones.get(zone)
        if entry is not None and entry[0] > self._now():
            return entry[1], entry[2]
        return None

    def _store_zone(self, zone, state, keys):
        with self._lock:
            if len(self._zones) > 20000:
                self._zones.clear()
            self._zones[zone] = (self._now() + self._cache_seconds, state, keys)

    def zone_keys(self, zone: dns.name.Name, depth: int = 0) -> tuple[str, dns.rrset.RRset | None]:
        """(SECURE, trusted DNSKEYs) / (INSECURE, None) / (BOGUS, None) for a zone."""
        cached = self._cached_zone(zone)
        if cached is not None:
            return cached
        if depth > 16:
            raise _ChainError("delegation chain too deep")

        keys_msg = self._query(zone, dns.rdatatype.DNSKEY)
        keys = _find(keys_msg.answer, zone, dns.rdatatype.DNSKEY)
        keys_sig = _signatures(keys_msg, keys_msg.answer, zone, dns.rdatatype.DNSKEY)

        if zone == dns.name.root:
            if keys is None or keys_sig is None:
                raise _ChainError("upstream returned no signed root DNSKEY set")
            trusted_ds = self._anchors
        else:
            ds_msg = self._query(zone, dns.rdatatype.DS)
            ds = _find(ds_msg.answer, zone, dns.rdatatype.DS)
            ds_sig = _signatures(ds_msg, ds_msg.answer, zone, dns.rdatatype.DS) if ds is not None else None
            if ds is None or ds_sig is None:
                parent = self._parent_zone(zone, ds_msg)
                parent_state = self.zone_keys(parent, depth + 1)[0]
                if parent_state != SECURE:
                    self._store_zone(zone, parent_state, None)
                    return parent_state, None
                if ds is not None:
                    # Unsigned DS from a signed parent: stripped signatures.
                    state = BOGUS
                elif ds_msg.rcode() != dns.rcode.NOERROR:
                    raise _ChainError(f"DS lookup for {zone} failed ({dns.rcode.to_text(ds_msg.rcode())})")
                else:
                    # The signed parent has to prove there's no DS.
                    proof = self._denial(ds_msg, parent).nodata(zone, dns.rdatatype.DS)
                    state = INSECURE if proof in (SECURE, INSECURE) else BOGUS
                self._store_zone(zone, state, None)
                return state, None
            signer = ds_sig[0].signer
            if signer == zone or not zone.is_subdomain(signer):
                self._store_zone(zone, BOGUS, None)
                return BOGUS, None
            parent_state, parent_keys = self.zone_keys(signer, depth + 1)
            if parent_state != SECURE:
                self._store_zone(zone, parent_state, None)
                return parent_state, None
            if not self._verify(ds, ds_sig, signer, parent_keys):
                self._store_zone(zone, BOGUS, None)
                return BOGUS, None
            trusted_ds = ds
            if keys is None or keys_sig is None:
                # A DS exists, so the zone must be signed.
                self._store_zone(zone, BOGUS, None)
                return BOGUS, None

        matching = self._keys_matching_ds(zone, keys, trusted_ds)
        if not matching:
            if zone == dns.name.root:
                raise _ChainError("root DNSKEYs don't match the trust anchors (check dns.dnssec_trust_anchors)")
            self._store_zone(zone, BOGUS, None)
            return BOGUS, None
        if not self._verify(keys, keys_sig, zone, matching):
            if zone == dns.name.root:
                raise _ChainError("root DNSKEY signature doesn't verify")
            self._store_zone(zone, BOGUS, None)
            return BOGUS, None
        self._store_zone(zone, SECURE, keys)
        return SECURE, keys

    @staticmethod
    def _keys_matching_ds(zone, keys, ds_rrset) -> dns.rrset.RRset | None:
        matching = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        for key in keys:
            for ds in ds_rrset:
                if dns.dnssec.key_id(key) != ds.key_tag or key.algorithm != ds.algorithm:
                    continue
                try:
                    candidate = dns.dnssec.make_ds(zone, key, ds.digest_type)
                except (dns.dnssec.UnsupportedAlgorithm, ValueError):
                    continue
                if candidate.digest == ds.digest:
                    matching.add(key)
        return matching if len(matching) else None

    def _verify(self, rrset, sigs, signer, keys) -> bool:
        try:
            dns.dnssec.validate(rrset, sigs, {signer: keys}, now=self._now())
            return True
        except dns.dnssec.ValidationFailure:
            return False

    def _parent_zone(self, zone: dns.name.Name, ds_msg: dns.message.Message) -> dns.name.Name:
        """The zone a DS lookup for `zone` was answered from."""
        for rrset in ds_msg.authority:
            if rrset.rdtype == dns.rdatatype.SOA and zone.is_subdomain(rrset.name) and zone != rrset.name:
                return rrset.name
        return self._zone_of(zone.parent())

    def _denial(self, message: dns.message.Message, zone: dns.name.Name) -> Denial:
        """The NSEC/NSEC3 records in the authority section that verify with `zone`'s keys."""
        state, keys = self.zone_keys(zone)
        verified = {dns.rdatatype.NSEC: [], dns.rdatatype.NSEC3: []}
        if state == SECURE:
            for rrset in message.authority:
                if rrset.rdtype not in verified:
                    continue
                sigs = _signatures(message, message.authority, rrset.name, rrset.rdtype)
                if sigs is not None and sigs[0].signer == zone and self._verify(rrset, sigs, zone, keys):
                    verified[rrset.rdtype].append(rrset)
        return Denial(zone, verified[dns.rdatatype.NSEC], verified[dns.rdatatype.NSEC3])

    def _zone_of(self, name: dns.name.Name) -> dns.name.Name:
        """The apex of the zone a name is in, from an SOA lookup."""
        with self._lock:
            entry = self._apex.get(name)
        if entry is not None and entry[0] > self._now():
            return entry[1]
        msg = self._query(name, dns.rdatatype.SOA)
        apex = None
        for rrset in list(msg.answer) + list(msg.authority):
            if rrset.rdtype == dns.rdatatype.SOA:
                apex = rrset.name
                break
        if apex is None:
            raise _ChainError(f"couldn't find the zone of {name}")
        with self._lock:
            if len(self._apex) > 20000:
                self._apex.clear()
            self._apex[name] = (self._now() + self._cache_seconds, apex)
        return apex

    # ------------------------------------------------------------ answers

    def _check_section(self, message, section, default_zone=None) -> list[str]:
        states = []
        # A CNAME synthesised from a DNAME is unsigned by design (RFC 6672).
        dnames = [r.name for r in section if r.rdtype == dns.rdatatype.DNAME]
        for rrset in section:
            if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.OPT):
                continue
            if (
                rrset.rdtype == dns.rdatatype.CNAME
                and any(rrset.name.is_subdomain(d) and rrset.name != d for d in dnames)
                and _signatures(message, section, rrset.name, rrset.rdtype) is None
            ):
                continue
            sigs = _signatures(message, section, rrset.name, rrset.rdtype)
            if sigs is not None:
                signer = sigs[0].signer
                if not rrset.name.is_subdomain(signer):
                    states.append(BOGUS)
                    continue
                state, keys = self.zone_keys(signer)
                if state != SECURE:
                    states.append(state)
                elif self._verify(rrset, sigs, signer, keys):
                    states.append(SECURE)
                else:
                    states.append(BOGUS)
            else:
                zone = default_zone if default_zone is not None else self._zone_of(rrset.name)
                state, _keys = self.zone_keys(zone)
                states.append(BOGUS if state == SECURE else INSECURE if state == INSECURE else state)
        return states

    @staticmethod
    def _final_name(message):
        """(name, type) the answer ends on after following its CNAME chain."""
        question = message.question[0]
        name, qtype = question.name, question.rdtype
        if qtype in (dns.rdatatype.CNAME, dns.rdatatype.ANY):
            return name, qtype
        seen = {name}
        while True:
            cname = _find(message.answer, name, dns.rdatatype.CNAME)
            if cname is None:
                return name, qtype
            name = cname[0].target
            if name in seen:
                raise _ChainError("CNAME loop")
            seen.add(name)

    def _check_wildcards(self, message) -> list[str]:
        """An answer synthesised from a wildcard (its RRSIG covers fewer labels
        than the owner name has) needs proof that the name itself doesn't exist."""
        states = []
        for rrset in message.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                continue
            sigs = _signatures(message, message.answer, rrset.name, rrset.rdtype)
            if sigs is None:
                continue
            labels = len(rrset.name) - 1
            if rrset.name.is_wild():
                labels -= 1
            sig_labels = min(sig.labels for sig in sigs)
            if sig_labels >= labels:
                continue
            signer = sigs[0].signer
            if self.zone_keys(signer)[0] != SECURE:
                continue  # already reported by _check_section
            source = rrset.name.split(sig_labels + 1)[1]
            states.append(self._denial(message, signer).wildcard(rrset.name, source))
        return states

    def _check_negative(self, message, name, qtype) -> list[str]:
        """NXDOMAIN / NODATA for (name, qtype): the authority section's
        signatures, then the NSEC/NSEC3 proof if the zone is signed."""
        soa = next((r for r in message.authority if r.rdtype == dns.rdatatype.SOA), None)
        if soa is not None and not name.is_subdomain(soa.name):
            return [BOGUS]
        # Without an SOA (stripped?), look the zone up ourselves.
        zone = soa.name if soa is not None else self._zone_of(name)
        states = self._check_section(message, message.authority, default_zone=zone)
        if self.zone_keys(zone)[0] != SECURE:
            return states
        denial = self._denial(message, zone)
        if message.rcode() == dns.rcode.NXDOMAIN:
            states.append(denial.nxdomain(name))
        else:
            states.append(denial.nodata(name, qtype))
        return states

    def validate(self, wire: bytes) -> str:
        """SECURE / INSECURE / BOGUS / INDETERMINATE for an upstream answer."""
        try:
            message = dns.message.from_wire(bytes(wire))
        except Exception:
            return INDETERMINATE
        if message.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) or len(message.question) != 1:
            return INDETERMINATE
        try:
            states = self._check_section(message, message.answer)
            states += self._check_wildcards(message)
            name, qtype = self._final_name(message)
            positive = any(
                rrset.name == name and (rrset.rdtype == qtype or qtype == dns.rdatatype.ANY)
                for rrset in message.answer
                if rrset.rdtype != dns.rdatatype.RRSIG
            )
            if not positive:
                states += self._check_negative(message, name, qtype)
            if not states:
                return INDETERMINATE
        except _ChainError as exc:
            logger.warning("DNSSEC chain check failed: %s", exc)
            return INDETERMINATE
        except Exception as exc:  # malformed upstream data, network trouble
            logger.debug("DNSSEC validation error: %s", exc)
            return INDETERMINATE
        if BOGUS in states:
            return BOGUS
        if all(state == SECURE for state in states):
            return SECURE
        if INDETERMINATE in states:
            return INDETERMINATE
        return INSECURE


def upstream_query_fn(forward: Callable[[bytes], bytes]) -> QueryFn:
    """A QueryFn that asks through `forward` (wire in, wire out) with DO and CD set."""

    def query(name: dns.name.Name, rdtype: int) -> dns.message.Message:
        request = dns.message.make_query(name, rdtype, want_dnssec=True, payload=1232)
        request.flags |= dns.flags.CD
        response = dns.message.from_wire(forward(request.to_wire()))
        if response.id != request.id:
            raise _ChainError("upstream answered a different query")
        return response

    return query
