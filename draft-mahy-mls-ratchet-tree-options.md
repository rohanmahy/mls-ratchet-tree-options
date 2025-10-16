---
title: Ways to convey the Ratchet Tree in Messaging Layer Security
abbrev: Ratchet tree options in MLS
docname: draft-mahy-mls-ratchet-tree-options-latest
ipr: trust200902
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
workgroup: MLS
area: sec
category: info
keyword:
 - ratchet_tree
 - GroupInfo
 - PartialGroupInfo

stand_alone: yes
pi: [toc, sortrefs, symrefs]

venue:
  group: MLS
  type: Working Group
  mail: mls@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/mls/
  github: rohanmahy/mls-ratchet-tree-options/
#  latest: https://github.com/rohanmahy/mls-ratchet-tree-options/latest

author:
 -  ins: R. Mahy
    name: Rohan Mahy
    organization: Rohan Mahy Consulting Services
    email: rohan.ietf@gmail.com

normative:

informative:


--- abstract

The Messaging Layer Security (MLS) protocol needs to share its
`ratchet_tree` object to welcome new clients into a group and in
external joins. While the protocol only defines a mechanism for sharing
the entire tree, most implementations use various optimizations to avoid
sending this structure repeatedly in large groups. This document describes
a way to convey these improvements in a standardized way and to
convey the parts of a GroupInfo object that are not visible to an
intermediary server.

--- middle

# Introduction

In the Messaging Layer Security (MLS) protocol {{!RFC9420}}, the members of
a group are organized into a ratchet tree, the full representation of which
is described in the `ratchet_tree` extension. The protocol specifies that
the full `ratchet_tree` can be included in Welcome messages or shared
externally, but describes no concrete way to convey it externally.
Likewise, when non-member clients want to join a group, they can do so using
an external commit. They require the GroupInfo and the `ratchet_tree`.

Many MLS implementations allow external commits to get the GroupInfo from a
central server. In the MIMI architecture {{?RFC9750}}, this server
is called the hub, and for brevity we will use that term generically to refer
to any central server that provides either GroupInfo or `ratchet_tree`
objects to new members (i.e. welcomed clients or externally joining clients).

When all handshake messages (commits and proposals) are sent as
`PublicMessage`s (or `SemiPrivateMessage`s
{{?I-D.mahy-mls-semiprivatemessage}}),
the hub can construct its own version of the `ratchet_tree` and most of the
GroupInfo object as proposals and commits arrive.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document assumes familiarity with terms and structs from the MLS specification ({{!RFC9420}}).

# Conveying the Ratchet Tree

The ratchet tree can be conveyed inline in its entirety. Alternatively,
this document describes how it can be referred to via an HTTPS URI, or
signaled that it is communicated out-of-band or reconstructed by the distribution service.

~~~ tls
enum {
  reserved(0),
  full(1),
  httpsUri(2),
  outOfBand(3),
  distributionService(4),
  (255)
} RatchetTreeRepresentation;

struct {
  RatchetTreeRepresentation representation;
  select (representation) {
    case full:
      Node ratchet_tree<V>;
    case httpsUrl:
      /* an HTTPS URL */
      opaque ratchet_tree_url<V>;
      opaque tree_signature<V>;
    case outOfBand:
      opaque tree_signature<V>;
    case distributionService:
      struct {};
  };
} RatchetTreeOption;
~~~

- `full` indicates that the complete `ratchet_tree` extension is included in
the RatchetTreeOption object.
- `httpsUri` indicates that the `ratchet_tree` can be downloaded from a
URI using the `https:` scheme.
- `outOfBand` indicates that the `ratchet_tree` is communicated or
reconstructed via an unspecified out-of-band application protocol.
- `distributionService` indicates that the `ratchet_tree` is reconstructed
by the Distribution Service from the handshake in the group. This is not
possible if any handshake messages are sent as an MLS `PrivateMessage`.

## Conveying the ratchet tree using HTTPS

This document defines a new MLS GroupContext extension `ratchet_tree_source_domains`.
When present, it contains a list of at least one domain name.

~~~ tls
struct {
    opaque domain<V>;
} Domain;

struct {
    Domain domains<V>
} DomainList;

DomainList ratchet_tree_source_domains;
~~~

When this extension is included in the GroupContext of a group, the URL where the `ratchet_tree` is fetched MUST come from one of the domains in the `ratchet_tree_source_domains.domains` list.


# Conveying the GroupInfo

In some systems the GroupInfo is sent to a hub with a full `ratchet_tree`
extension always included with every commit. This is used in systems where
the hub may or may not track the membership of the group, but does not keep
the entire `ratchet_tree` data structure. As group size increases, the size
of the `ratchet_tree` extension in the GroupInfo scales roughly linearly.
Even using `basic` credentials, this object gets large quickly. If `x509`
credentials are used, the size increases much more rapidly, and if a
post-quantum ciphersuite (for example {{?I-D.ietf-mls-pq-ciphersuites}}) is
used, the size will increase even more rapidly with each new member.

In some systems that require unencrypted handshake messages, the hub tracks
commits as they are sent and constructs changes to the `ratchet_tree` as
each handshake is accepted. The hub could also recreate most of the fields
of a GroupInfo, with the exception of the GroupInfo signature and the
GroupInfo extensions, by inspecting those same unencrypted handshake
messages . This document defines a `PartialGroupInfo` struct that contains
these missing fields. `PartialGroupInfo` can be included with a commit and
any referenced proposals to reconstruct a GroupInfo and `ratchet_tree` from
the GroupInfo and `ratchet_tree` included in the previous epoch.

~~~ tls
enum {
  no_ratchet_tree(0),
  present(1),
  removed(2),
  added(3),
  (255)
} RatchetTreePresence;

struct {
  RatchetTreePresence ratchet_tree_presence;
  /* GroupInfo extensions excluding ratchet_tree */
  Extension group_info_extensions<V>;
  opaque signature<V>;
} PartialGroupInfo;
~~~

The value of `ratchet_tree_presence` is defined as follows:

- `no_ratchet_tree`: the `ratchet_tree` extension appears in neither the
  current nor previous epochs.
- `present`: there is a `ratchet_tree` extension in both the current and
  previous epochs.
- `removed`: there was a `ratchet_tree` extension in the previous epoch
  but none in the current epoch.
- `added`: there is a `ratchet_tree` extension in the current epoch
  but there was none in the previous epoch.

The `group_info_extensions` object is the list of GroupInfo
extensions, omitting any `ratchet_tree` extension (if present). The only
other GroupInfo extension defined in the base protocol is `external_pub`,
the public key of the external commiter. The `group_info_extensions` is
often an empty list.

The `signature` in the PartialGroupInfo is the signature produced by the
committer (represented by its leaf index in the GroupInfo as the `signer`).

# Security Considerations

TODO Security


# IANA Considerations

## ratchet_tree_source_domains MLS Extension Type

This document registers the `ratchet_tree_source_domains` Extension Type, using the template below:

- Value: TBD1 (new assignment by IANA)
- Name: ratchet_tree_source_domains
- Messages: GC
- Recommended: Y
- Reference: RFC XXXX


--- back

# Change Log

## Changes between -01 and -02

- Added ratchet_tree_source_domains extension

## Changes between -00 and -01

- Removed ratchet tree patch options and notation.
- Added `ratchet_tree_presence` options for out-of-band, via HTTPS, and
reconstructed by the delivery service.

# Acknowledgments
{:numbered="false"}

The PartialGroupInfo was first introduced in
{{?I-D.robert-mimi-delivery-service}}.
