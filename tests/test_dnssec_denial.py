# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""NSEC / NSEC3 denial-of-existence proofs in local DNSSEC validation.

example. is an NSEC zone with www (A), a wildcard *.w and an unsigned
delegation unsigned.example.; n3. is an NSEC3 zone (opt-out) with www and
an unsigned delegation child.n3."""

import base64

import dns.dnssec
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from app.dnssec_denial import Denial
from app.dnssec_validate import BOGUS, INSECURE, ROOT_TRUST_ANCHORS, SECURE, LocalValidator, _parse_anchors
from tests.test_dnssec_local import N, World, Zone


def _nsec3_owner(name, zone, salt=b"", iterations=0):
    return f"{dns.dnssec.nsec3_hash(name, salt, iterations, 1)}.{zone}"


class DenialWorld(World):
    def __init__(self, iterations=0, optout=True):
        super().__init__()
        ex = self.example
        self.nsec = {
            owner: ex.rrset(owner, "NSEC", value)
            for owner, value in {
                "example.": "unsigned.example. NS SOA RRSIG NSEC DNSKEY",
                "unsigned.example.": "*.w.example. NS RRSIG NSEC",
                "*.w.example.": "www.example. A RRSIG NSEC",
                "www.example.": "example. A RRSIG NSEC",
            }.items()
        }
        self.soa = self.answers[(N("example."), dns.rdatatype.SOA)]
        self.add("unsigned.example.", "DS", authority=[*self.soa, *self.signed(self.nsec["unsigned.example."])])
        u_soa = ex.rrset("unsigned.example.", "SOA", "ns.unsigned.example. a.unsigned.example. 1 3600 600 86400 300")
        self.add("unsigned.example.", "SOA", u_soa)
        self.add("www.unsigned.example.", "SOA", authority=[u_soa])
        self.add("unsigned.example.", "DNSKEY")

        # n3.: signed, delegated from the root, denial by NSEC3.
        self.n3 = n3 = Zone("n3.")
        ds = dns.rrset.from_rdata("n3.", 300, n3.ds())
        self.add("n3.", "DS", ds, self.root.sign(ds))
        self.add("n3.", "DNSKEY", n3.keys, n3.sign(n3.keys))
        self.n3_soa = n3.rrset("n3.", "SOA", "ns.n3. admin.n3. 1 3600 600 86400 300")
        self.add("n3.", "SOA", self.n3_soa, n3.sign(self.n3_soa))
        self.iterations = iterations
        names = {"n3.": "NS SOA RRSIG DNSKEY NSEC3PARAM", "www.n3.": "A RRSIG"}
        owners = sorted((_nsec3_owner(name, "n3.", iterations=iterations), types) for name, types in names.items())
        self.nsec3 = {}
        for i, (owner, types) in enumerate(owners):
            next_owner = owners[(i + 1) % len(owners)][0]
            flags = 1 if optout else 0
            rrset = n3.rrset(owner, "NSEC3", f"1 {flags} {iterations} - {next_owner.split('.')[0]} {types}")
            self.nsec3[owner] = rrset
        self.add("n3.", "DS", ds, self.root.sign(ds))
        self.add("child.n3.", "DS", authority=[self.n3_soa, n3.sign(self.n3_soa), *self.all_nsec3()])
        c_soa = n3.rrset("child.n3.", "SOA", "ns.child.n3. a.child.n3. 1 3600 600 86400 300")
        self.add("child.n3.", "SOA", c_soa)
        self.add("www.child.n3.", "SOA", authority=[c_soa])
        self.add("child.n3.", "DNSKEY")

    def signed(self, rrset, zone=None):
        return [rrset, (zone or self.example).sign(rrset)]

    def all_nsec3(self):
        out = []
        for rrset in self.nsec3.values():
            out += self.signed(rrset, self.n3)
        return out

    def negative(self, qname, rdtype, authority, nxdomain=False):
        request = dns.message.make_query(qname, rdtype, want_dnssec=True)
        response = dns.message.make_response(request)
        if nxdomain:
            response.set_rcode(dns.rcode.NXDOMAIN)
        response.authority.extend(authority)
        return response.to_wire()


def _v(world):
    return LocalValidator(world.query, anchors=[world.anchor])


# ---------------------------------------------------------------- NSEC


def test_nsec_nxdomain_proven():
    w = DenialWorld()
    # nope.example. sits between example. and unsigned.example., and so does *.example.
    proof = [*w.soa, *w.signed(w.nsec["example."])]
    assert _v(w).validate(w.negative("nope.example.", "A", proof, nxdomain=True)) == SECURE


def test_nsec_nxdomain_without_or_with_wrong_proof_is_bogus():
    w = DenialWorld()
    v = _v(w)
    assert v.validate(w.negative("nope.example.", "A", list(w.soa), nxdomain=True)) == BOGUS
    wrong = [*w.soa, *w.signed(w.nsec["www.example."])]
    assert v.validate(w.negative("nope.example.", "A", wrong, nxdomain=True)) == BOGUS
    # An existing name can't be denied with the NSEC that names it.
    assert v.validate(w.negative("www.example.", "A", [*w.soa, *w.signed(w.nsec["www.example."])], nxdomain=True)) == BOGUS


def test_nsec_proof_must_be_signed_by_the_zone():
    w = DenialWorld()
    impostor = Zone("example.")
    proof = [*w.soa, w.nsec["example."], impostor.sign(w.nsec["example."])]
    assert _v(w).validate(w.negative("nope.example.", "A", proof, nxdomain=True)) == BOGUS
    # Stripping the NSEC signatures doesn't help either.
    assert _v(w).validate(w.negative("nope.example.", "A", [*w.soa, w.nsec["example."]], nxdomain=True)) == BOGUS


def test_nsec_nodata():
    w = DenialWorld()
    v = _v(w)
    proof = [*w.soa, *w.signed(w.nsec["www.example."])]
    assert v.validate(w.negative("www.example.", "AAAA", proof)) == SECURE
    # The NSEC says www has an A record, so it can't deny one.
    assert v.validate(w.negative("www.example.", "A", proof)) == BOGUS
    assert v.validate(w.negative("www.example.", "AAAA", list(w.soa))) == BOGUS


def test_nsec_delegation_cannot_deny_child_data():
    w = DenialWorld()
    # The parent-side NSEC for unsigned.example. says nothing about names below it.
    proof = [*w.soa, *w.signed(w.nsec["unsigned.example."])]
    assert _v(w).validate(w.negative("a.unsigned.example.", "A", proof, nxdomain=True)) == BOGUS


def test_negative_answer_without_soa_still_needs_a_proof():
    w = DenialWorld()
    w.add("nope.example.", "SOA", authority=list(w.soa))
    assert _v(w).validate(w.negative("nope.example.", "A", [], nxdomain=True)) == BOGUS


def test_nsec_wildcard_answer():
    w = DenialWorld()
    ex = w.example
    wild = ex.rrset("*.w.example.", "A", "192.0.2.7")
    sig = ex.sign(wild)
    expanded = ex.rrset("a.w.example.", "A", "192.0.2.7")
    expanded_sig = dns.rrset.RRset(N("a.w.example."), dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.A)
    expanded_sig.add(sig[0], 300)
    v = _v(w)
    request = dns.message.make_query("a.w.example.", "A", want_dnssec=True)
    response = dns.message.make_response(request)
    response.answer.extend([expanded, expanded_sig])
    # No proof that a.w.example. doesn't exist: could hide a real record.
    assert v.validate(response.to_wire()) == BOGUS
    response.authority.extend(w.signed(w.nsec["*.w.example."]))
    assert v.validate(response.to_wire()) == SECURE


def test_nsec_insecure_delegation_is_proven():
    w = DenialWorld()
    a = w.example.rrset("www.unsigned.example.", "A", "192.0.2.9")
    assert _v(w).validate(w.response("www.unsigned.example.", "A", a)) == INSECURE


def test_unproven_missing_ds_is_bogus():
    w = DenialWorld()
    # A "no DS" answer for example. without the root's NSEC: a downgrade attempt.
    w.add("example.", "DS", authority=[w.root_soa, w.root.sign(w.root_soa)])
    a = w.example.rrset("www.example.", "A", "6.6.6.6")
    assert _v(w).validate(w.response("www.example.", "A", a)) == BOGUS
    # Same for a name in a zone the parent never proved unsigned.
    w2 = DenialWorld()
    w2.add("unsigned.example.", "DS", authority=list(w2.soa))
    a = w2.example.rrset("www.unsigned.example.", "A", "6.6.6.6")
    assert _v(w2).validate(w2.response("www.unsigned.example.", "A", a)) == BOGUS


# ---------------------------------------------------------------- NSEC3


def test_nsec3_nxdomain_and_nodata():
    w = DenialWorld()
    v = _v(w)
    soa = [w.n3_soa, w.n3.sign(w.n3_soa)]
    assert v.validate(w.negative("nope.n3.", "A", [*soa, *w.all_nsec3()], nxdomain=True)) == SECURE
    assert v.validate(w.negative("www.n3.", "AAAA", [*soa, *w.all_nsec3()])) == SECURE
    assert v.validate(w.negative("www.n3.", "A", [*soa, *w.all_nsec3()])) == BOGUS
    assert v.validate(w.negative("www.n3.", "A", [*soa, *w.all_nsec3()], nxdomain=True)) == BOGUS
    assert v.validate(w.negative("nope.n3.", "A", soa, nxdomain=True)) == BOGUS


def test_nsec3_opt_out_delegation_is_insecure():
    w = DenialWorld(optout=True)
    a = w.n3.rrset("www.child.n3.", "A", "192.0.2.10")
    assert _v(w).validate(w.response("www.child.n3.", "A", a)) == INSECURE


def test_nsec3_without_opt_out_needs_a_matching_record():
    w = DenialWorld(optout=False)
    soa = [w.n3_soa, w.n3.sign(w.n3_soa)]
    w.add("child.n3.", "DS", authority=[*soa, *w.all_nsec3()])
    a = w.n3.rrset("www.child.n3.", "A", "192.0.2.10")
    assert _v(w).validate(w.response("www.child.n3.", "A", a)) == BOGUS


def test_nsec3_too_many_iterations_is_insecure():
    w = DenialWorld(iterations=500)
    soa = [w.n3_soa, w.n3.sign(w.n3_soa)]
    assert _v(w).validate(w.negative("nope.n3.", "A", [*soa, *w.all_nsec3()], nxdomain=True)) == INSECURE


def test_nsec3_closest_encloser_rules():
    zone = N("z.")
    hashes = {name: dns.dnssec.nsec3_hash(N(name), b"", 0, 1) for name in ("z.", "sub.z.")}

    def nsec3(owner_name, types, next_hash, flags=0):
        rrset = dns.rrset.from_text(f"{hashes[owner_name]}.z.", 300, "IN", "NSEC3", f"1 {flags} 0 - {next_hash} {types}")
        return rrset

    # Only the apex record, whose span covers everything else.
    apex = nsec3("z.", "NS SOA RRSIG", hashes["z."])
    denial = Denial(zone, nsec3=[apex])
    assert denial.nxdomain(N("x.z.")) == SECURE
    # Names below a delegation can't be proven by the parent.
    cut = nsec3("sub.z.", "NS", hashes["z."])
    assert Denial(zone, nsec3=[apex, cut]).nxdomain(N("a.sub.z.")) == BOGUS
    # Records from another zone are ignored.
    assert Denial(N("other."), nsec3=[apex]).nxdomain(N("x.other.")) == BOGUS
    assert base64.b32hexdecode(hashes["z."])  # sanity: valid base32hex


# ---------------------------------------------------------------- anchors


def test_builtin_root_anchors_are_iana_ksk_2017_and_2024():
    anchors = {(ds.key_tag, ds.algorithm, ds.digest_type, ds.digest.hex().upper()) for ds in _parse_anchors(ROOT_TRUST_ANCHORS)}
    assert anchors == {
        (20326, 8, 2, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
        (38696, 8, 2, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
    }
