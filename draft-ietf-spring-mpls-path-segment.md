---
v: 3
docname: draft-ietf-spring-mpls-path-segment-09
cat: std
stream: IETF
pi:
  toc: 'yes'
  tocompact: 'yes'
  tocdepth: '3'
  tocindent: 'yes'
  symrefs: 'yes'
  sortrefs: 'yes'
  comments: 'yes'
  inline: 'yes'
  compact: 'yes'
  subcompact: 'no'
title: Path Segment in MPLS Based Segment Routing Network
abbrev: Path Segment in SR-MPLS
area: Routing Area
wg: SPRING Working Group
date: 2023-05-30

author:
- name: Weiqiang Cheng
  org: China Mobile
  email: chengweiqiang@chinamobile.com
- name: Han Li
  org: China Mobile
  email: lihan@chinamobile.com
- name: Cheng Li
  org: Huawei Technologies Co., Ltd
  country: China
  email: c.l@huawei.com
- name: Rakesh Gandhi
  org: Cisco Systems, Inc.
  country: Canada
  email: rgandhi@cisco.com
- name: Royi Zigler
  org: Broadcom
  email: royi.zigler@broadcom.com

contributor:
- name: Mach(Guoyi) Chen
  org: Huawei Technologies Co., Ltd
  email: mach.chen@huawei.com
- name: Lei Wang
  org: China Mobile
  email: wangleiyj@chinamobile.com
- name: Aihua Liu
  org: ZTE Corp
  email: liu.aihua@zte.com.cn
- name: Greg Mirsky
  org: ZTE Corp
  email: gregimirsky@gmail.com
- name: Gyan S. Mishra
  org: Verizon Inc.
  email: gyan.s.mishra@verizon.com

normative:
  RFC8402:
  RFC8660:
informative:
  RFC4426:
  RFC5586:
  RFC5654:
  RFC8662:
  RFC8664:
  RFC7799:
  RFC8986:
  RFC8992:
  RFC9256:

--- abstract


A Segment Routing (SR) path is identified by an SR segment list. Only
the complete segment list can identify the end-to-end SR path, and a
sub-set of segments from the segment list cannot distinguish one SR path
from another as they may be partially congruent. SR path identification
is a pre-requisite for various use-cases such as Performance Measurement
(PM), bidirectional paths correlation, and end-to-end 1+1 path
protection.

In SR for MPLS data plane (SR-MPLS), the segment identifiers are
stripped from the packet through label popping as the packet transits
the network. This means that when a packet reaches the egress of the SR
path, it is not possible to determine on which SR path it traversed the
network.

This document defines a new type of segment that is referred to as
Path Segment, which is used to identify an SR path in an SR-MPLS
network. When used, it is inserted by the ingress node of the SR path
and immediately follows the last segment identifier in the segment list
of the SR path. The Path Segment is preserved until it reaches the
egress node for SR path identification and correlation.

--- middle

# Introduction

Segment Routing (SR) {{RFC8402}} leverages the
source-routing paradigm to steer packets from a source node through a
controlled set of instructions, called segments, by prepending the
packet with an SR header in the MPLS data plane SR-MPLS {{RFC8660}}
through a label stack or IPv6 data plane using an SRH
header via SRv6 {{RFC8986}} to construct an SR path.

In an SR-MPLS network, when a packet is transmitted along an SR path,
the labels in the MPLS label stack will be swapped or popped. So that no
label or only the last label (e.g. Explicit-Null label) may be left in
the MPLS label stack when the packet reaches the egress node. Thus, the
egress node cannot determine along which SR path the packet came.

However, to support various use-cases in SR-MPLS networks, like
end-to-end 1+1 path protection (Live-Live case) {{RFC4426}},
bidirectional path {{RFC5654}}, or Performance Measurement (PM)
{{RFC7799}}, the ability to implement path identification on the egress
node is a pre-requisite.

Therefore, this document introduces a new segment type that is
referred to as the Path Segment. A Path Segment is defined to uniquely
identify an SR path in an SR-MPLS network. It MAY be used by the egress
nodes for path identification hence to support various use-cases
including SR path PM, end-to-end 1+1 SR path protection, and
bidirectional SR paths correlation.

## Requirements Language

{::boilerplate bcp14-tagged}

## Abbreviations

DM: Delay Measurement.

LM: Loss Measurement.

MPLS: Multiprotocol Label Switching.

MSD: Maximum SID Depth.

PM: Performance Measurement.

PSID: Path Segment ID.

SID: Segment ID.

SL: Segment List.

SR: Segment Routing.

SRLB: SR Local Block

SRGB: SR Global Block

SR-MPLS: Instantiation of SR on the MPLS data plane.

SRv6: Instantiation of SR on the IPv6 data plane.



# Path Segment

A Path Segment is a single label that is assigned from the Segment
Routing Local Block (SRLB) {{RFC8402}} or Segment Routing
Global Block (SRGB) {{RFC8402}} or dynamic MPLS label pool
of the egress node of an SR path. Whether a Path Segment is allocated
from the SRLB, SRGB, or a dynamic range depends on specific use cases. If
the Path Segment is only used by the egress node to identify a SR path,
the SRLB, SRGB or dynamic MPLS label pool can be used. If the Path
Segment is used by an intermediate node to identify a SR path, the SRGB
MUST be used. Three use cases are introduced in Section 5, 6, and 7 of
this document.

When a Path Segment is used, the Path Segment MUST be inserted at the
ingress node and MUST immediately follow the last label of the SR path,
in other words, inserted after the routing segment
(adjacency/node/prefix segment) pointing to the egress node.

The term of SR path used in this document is a general term that can
be used to describe a SR Policy, a Candidate-Path (CP), or a Segment-List
(SL) {{RFC9256}}. Therefore,
the Path Segment may be used to identify an SR Policy, its CP, or a SL
terminating on an egress node depending on the use-case.

The value of the TTL field in the MPLS label stack entry containing
the Path Segment MUST be set to the same value as the TTL of the last
label stack entry for the last segment in the SR path. If the Path
Segment is the bottom label, the S bit MUST be set.

Normally, an intermediate node will not process the Path Segment label in the label stack. But in some use cases, an intermediate node MAY process the Path Segment label in the label stack. In these cases, the Path Segment label MUST be learned before processing. The detailed use cases and processing is out of the scope of this document.

A Path Segment can be used in the case of Penultimate Hop Popping
(PHP), where some labels are be popped off at the penultimate hop of an
SR path, but the Path Segment MUST NOT be popped off until it reaches at
the egress node.

The egress node MUST pop the Path Segment. The egress node MAY use
the Path Segment for further processing. For example, when performance
measurement is enabled on the SR path, it can trigger packet counting or
timestamping.

In some deployments, service labels may be added after the Path
Segment label in the MPLS label stack. In this case, the egress node
MUST be capable of processing more than one label. The additional
processing required, may have an impact on forwarding performance.

Generic Associated Label (GAL) is used for Operations, Administration
and Maintenance (OAM) in MPLS networks {{RFC5586}}. When
GAL is used, it MUST be added at the bottom of the label stack after the
Path Segment label.

Entropy label and Entropy Label Indicator (ELI) as described in {{RFC8662}} for SR-MPLS path, can be placed before or after the
Path Segment label in the MPLS label stack.

The SR path computation needs to know the Maximum SID Depth (MSD)
that can be imposed at each node/link of a given SR path {{RFC8664}}. This ensures that the SID stack depth of a computed
path does not exceed the number of SIDs the node is capable of imposing.
The MSD used for path computation MUST include the Path Segment
label.

The label stack with Path Segment is shown in {{figure1}}:

~~~~
            +--------------------+
            |       ...          |
            +--------------------+
            |      Label 1       |
            +--------------------+
            |      Label 2       |
            +--------------------+
            |       ...          |
            +--------------------+
            |      Label n       |
            +--------------------+
            |     Path Segment   |
            +--------------------+
            |       ...          |
            +--------------------+
            ~       Payload      ~
            +--------------------+
~~~~
{: #figure1 title="Label Stack with Path Segment"}

Where:

* The Labels 1 to n are the segment label stack used to direct how
  to steer the packets along the SR path.

* The Path Segment identifies the SR path in the context of the
  egress node of the SR path.

There may be multiple paths (or sub-path(s)) carried in the
label stack, for each path (or sub-path), there may be a corresponding
Path Segment carried. A use case can be found in Section 4.

In addition, adding a Path Segment to a label stack will increase the
depth of the label stack, the Path Segment should be accounted when
considering Maximum SID Depth (MSD){{RFC8992}}.


# Path Segment Allocation and Distribution

There are two ways that leverage a centralized controller (e.g., SDN
controller) to assign and distribute the Path Segment. One is the Path
Computation Element Communication Protocol (PCEP) based Path Segment
allocation for SR Policy, the other is BGP based Path Segment allocation for SR Policy. The detailed solutions are out of the scope of this document and defined in other documents.

For both ways, the controller MUST make sure (e.g., by some capability
discovery mechanisms outside the scope of this document) that the
egress node knows the Path Segment and it can process it, as well as
the label does not collide with any label allocation done by the
egress node.

If an egress cannot support the use of the Path Segment Label, it MUST reject the attempt to configure the label.

# Nesting of Path Segments

Binding SID (BSID) {{RFC8402}} can be used for SID list
compression. With BSID, an end-to-end SR path can be split into several
sub-paths, each sub-path is identified by a BSID. Then an end-to-end SR
path can be identified by a list of BSIDs, therefore, it can provide
better scalability.

BSID and Path SID (PSID) can be combined to achieve both sub-path and
end-to-end path monitoring. A reference model for such a combination in
(Figure 2) shows an end-to-end path (A->D) that spans three domains
(Access, Aggregation and Core domain) and consists of three sub-paths,
one in each sub-domain (sub-path (A->B), sub-path (B->C) and
sub-path (C->D)). Each sub-path is allocated a BSID. For nesting the
sub-paths, each sub-path is allocated a PSID. Then, the SID list of the
end-to-end path can be expressed as \<BSID1, BSID2, ..., BSIDn,
e-PSID>, where the e-PSID is the PSID of the end-to-end path. The SID
list of a sub-path can be expressed as \<SID1, SID2, ...SIDn,
s-PSID>, where the s-PSID is the PSID of the sub-path.

{{figure2}} shows the details of the label stacks when PSID and BSID are
used to support both sub-path and end-to-end path monitoring in a
multi-domain scenario.

~~~~
         /--------\       /--------\       /--------\
       /            \   /            \   /            \
     A{    Access    }B{  Aggregation }C{     Core     }D
       \            /   \            /   \            /
         \--------/       \--------/       \--------/
       Sub-path(A->B)    Sub-path(B->C)   Sub-path(C->D)
    |<--------------->|<-------------->|<-------------->|
                          E2E Path(A->D)
    |<------------------------------------------------->|

 +------------+
 ~A->B SubPath~
 +------------+  +------------+
 |s-PSID(A->B)|  ~B->C SubPath~
 +------------+  +------------+
 | BSID(B->C) |  |s-PSID(B->C)|
 +------------+  +------------+  +------------+
 | BSID(C->D) |  | BSID(C->D) |  ~C->D SubPath~
 +------------+  +------------+  +------------+  +------------+
 |e-PSID(A->D)|  |e-PSID(A->D)|  |e-PSID(A->D)|  |e-PSID(A->D)|
 +------------+  +------------+  +------------+  +------------+
~~~~
{: #figure2 title="Nesting of Path Segments"}


# Path Segment for Performance Measurement

As defined in {{RFC7799}}, performance measurement can
be classified into Passive, Active, and Hybrid measurement. Since Path
Segment is encoded in the SR-MPLS Label Stack as shown in Figure 1,
existing implementation on the egress node can be leveraged for
measuring packet counts using the incoming SID (the Path Segment). A
different scheme such as carrying such identifier after the bottom of
the label stack may require new implementation.

For Passive performance measurement, path identification at the
measuring points is the pre-requisite. Path Segment can be used by the
measuring points (e.g., the ingress and egress nodes of the SR path or a
centralized controller) to correlate the packet counts and timestamps
from the ingress and egress nodes for a specific SR path, then packet
loss and delay can be calculated for the end-to-end path,
respectively.

Path Segment can also be used for Active performance measurement for
an SR path in SR-MPLS networks for collecting packet counters and
timestamps from the egress node using probe messages.

Path Segment can also be used for In-situ OAM for SR-MPLS to identify
the SR Path associated with the in-situ data fields in the data packets
on the egress node.

Path Segment can also be used for In-band PM for SR-MPLS to identify
the SR Path associated with the collected performance metrics.


# Path Segment for Bidirectional SR Path

In some scenarios, for example, mobile backhaul transport networks,
there are requirements to support bidirectional paths, and the path is
normally treated as a single entity. The both directions of the path
have the same fate, for example, failure in one direction will result in
switching traffic at both directions. MPLS supports this by introducing
the concepts of co-routed bidirectional LSP and associated bidirectional
LSP {{RFC5654}}.

In the current SR architecture, an SR path is a unidirectional path
{{RFC8402}}.
In order to support bidirectional SR paths, a straightforward way is
to bind two unidirectional SR paths to a single bidirectional SR
path. Path Segments can then be used to identify and correlate the
traffic for the two unidirectional SR paths at both ends of the
bidirectional path.



# Path Segment for End-to-end Path Protection

For end-to-end 1+1 path protection (i.e., Live-Live case), the egress
node of the path needs to know the set of paths that constitute the
primary and the secondaries, in order to select the primary path packets
for onward transmission, and to discard the packets from the secondaries {{RFC4426}}.

To do this in Segment Routing, each SR path needs a path identifier
that is unique at the egress node. For SR-MPLS, this can be the Path
Segment label allocated by the egress node.

There then needs to be a method of binding this SR path identifiers
into equivalence groups such that the egress node can determine for
example, the set of packets that represent a single primary path. It is
obvious that this equivalence group can be instantiated in the network
by an SDN controller using the Path Segments of the SR paths.


# Security Considerations {#Security}

Path Segment in SR-MPLS does not introduce any new behavior or any
change in the way the MPLS data plane works.
{{Section 8.1 of RFC8402}} describes the security consideration for SR-MPLS.
Path segment is additional metadata that is added to the packet
consisting of the SR path.

An attacker could exploit path segment to manipulate the accounting
of SR traffic at the egress. Path segment could also be used to monitor
traffic patterns for the E2E paths. The control protocols used to
allocate path segments could also be exploited to disseminate incorrect
path segment information. Note that, the path segment is imposed at the
ingress and removed at the egress boundary and is not leaked out of the
administered domain.


# IANA Considerations {#IANA}

This document does not require any IANA actions.


--- back

# Acknowledgements {#Acknowledgements}
{: numbered="no"}

The authors would like to thank Adrian Farrel, Stewart Bryant,
Shuangping Zhan, Alexander Vainshtein, Andrew G. Malis, Ketan
Talaulikar, Shraddha Hegde, and Loa Andersson for their review,
suggestions and comments to this document.

The authors would like to acknowledge the contribution from Alexander
Vainshtein on "Nesting of Path Segments".

--- contributor

The following people have substantially contributed to this
document: