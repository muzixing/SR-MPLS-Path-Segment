---
v: 3
docname: draft-ietf-spring-mpls-path-segment-11
cat: std
stream: IETF
consensus: true
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
date: 2023-08-29

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
  RFC6790:
  RFC8664:
  RFC7799:

--- abstract


A Segment Routing (SR) path is identified by an SR segment list. A
sub-set of segments from the segment list cannot distinguish one SR path
from another as they may be partially congruent. SR path identification
is a pre-requisite for various use-cases such as Performance Measurement
(PM), and end-to-end 1+1 path protection.

In SR for MPLS data plane (SR-MPLS), an Egress node can not determine on which SR path a packet traversed the network from the label stack because the segment identifiers are stripped from the label stack as the packet transits the network. 

This document defines Path Segment to identify an SR path on the egress node of the path. 

--- middle

# Introduction

Segment Routing (SR) {{RFC8402}} leverages the
source-routing paradigm to steer packets from a source node through a
controlled set of instructions, called segments, by prepending the
packet with an SR header in the MPLS data plane SR-MPLS {{RFC8660}}
through a label stack to construct an SR path.

In an SR-MPLS network, when a packet is transmitted along an SR path,
the labels in the MPLS label stack will be swapped or popped. So that no
label or only the last label (e.g. a service label or an Explicit-Null label) may be left in the MPLS label stack when the packet reaches the egress node. Thus, the egress node cannot use the SR label stack to determine along which SR path the packet came. 

However, to support various use-cases in SR-MPLS networks, like
end-to-end 1+1 path protection (Live-Live case) {{psid-for-protection}},
bidirectional path {{psid-for-bpath}}, or Performance Measurement (PM)
{{psid-for-pm}}, the ability to implement path identification on the egress
node is a pre-requisite. 

Therefore, this document introduces a new segment type that is
referred to as the Path Segment. A Path Segment is defined to uniquely
identify an SR path on the egress node of the path. It MAY be used by the egress
nodes for path identification hence to support various use-cases
including SR path PM, end-to-end 1+1 SR path protection, and
bidirectional SR paths correlation. Note that, Per-path states will be maintained in the egress node due to the requirements in these use cases, though in normal cases that the per-path states will be maintained in the ingress node only in the SR architecture.

## Requirements Language

{::boilerplate bcp14-tagged}

## Abbreviations and Terms

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

Sub-Path: A sub-path is a part of the a path, which contains a sub-set of the nodes and links of the path.  


# Path Segment

A Path Segment Identifier(PSID) is a single label that is assigned from the Segment Routing Local Block (SRLB) {{RFC8402}} or Segment Routing Global Block (SRGB) {{RFC8402}} or dynamic MPLS label pool of the egress node of an SR path. Whether a PSID is allocated from the SRLB, SRGB, or a dynamic range depends on specific use cases. If the PSID is only used by the egress node to identify an SR path, the SRLB, SRGB or dynamic MPLS label pool can be used. Three use cases are introduced in Section 5, 6, and 7 of this document.

The term of SR path used in this document is a path described by a Segment-List (SL). A PSID is used to identify a Segment List. However, one PSID can be used to identify multiple Segment Lists in some use cases if needed. For example, all the Segment lists in a Candidate path can use a single PSID, and all the Segment Lists in an SR policy can share the same PSID, if customers would like to aggregate the data among the Segment Lists. How to use the PSID to Segment Lists depends on the requirements of the use cases.

When a PSID is used, the PSID MUST be inserted at the ingress node and MUST immediately follow the last label of the SR path, in other words, inserted after the routing segment (adjacency/node/prefix segment) pointing to the egress node of the SR path. Otherwise, the PSID may be processed by an intermediate node, which may cause error in forwarding because of mis-matching if the PSID is allocated from a SRLB.

The value of the TTL field in the MPLS label stack entry containing the PSID can be set to any value including 0, or the same value as the TTL of the last label stack entry for the last segment in the SR path. If the Path Segment is the bottom label, the S bit MUST be set.

A PSID can be used in the case of Penultimate Hop Popping (PHP), where some labels are be popped off at the penultimate hop of an SR path. As per regular MPLS processing, the label below (including the PSID in this case) will not be popped by the penultimate node.

The egress node MUST pop the PSID. The egress node MAY use the PSID for further processing. For example, when performance measurement is enabled on the SR path, it can trigger packet counting or timestamping.

The addition of the PSID will require the egress to read and process the PSID label in addition to the regular processing (such as a below MPLS label or the MPLS payload). The additional processing required, may have an impact on forwarding performance。

Generic Associated Label (GAL) MAY be used for Operations, Administration and Maintenance (OAM) in MPLS networks. As per {{RFC5586}}, when GAL is used, the ACH appears immediately after the bottom of the label stack.


If Entropy Label is also used on this egress node, as per {{RFC6790}} the Entropy label Indicator (ELI) and Entropy Label (EL) would be placed before the tunnel label and hence does not interfere with the PSID which is placed below. 

The SR path computation needs to know the Maximum SID Depth (MSD) that can be imposed at the ingress node of a given SR path {{RFC8664}}. This ensures that the SID stack depth of a computed path does not exceed the number of SIDs the node is capable of imposing. As per RFC8491 the MSD signals the total number of MPLS labels that can be imposed. This includes the PSID.

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
            |        PSID        |
            +--------------------+
            ~       Payload      ~
            +--------------------+
~~~~
{: #figure1 title="Label Stack with Path Segment"}

Where:

* The Labels 1 to n are the segment label stack used to direct how
  to steer the packets along the SR path.

* The PSID identifies the SR path in the context of the egress node of the SR path.

There may be multiple paths (or sub-path(s)) carried in the
label stack, for each path (or sub-path), there may be a corresponding
Path Segment carried. A use case can be found in {{psid-nesting}}.

Signaling of the PSID between the egress, ingress and possibly a centralized controller is out of the scope of this document.


# Use cases

This section describes use cases which can leveage the Path Segment.

## Path Segment for Performance Measurement {#psid-for-pm}

As defined in {{RFC7799}}, performance measurement can
be classified into Passive, Active, and Hybrid measurement. Since Path
Segment is encoded in the SR-MPLS Label Stack as shown in Figure 1,
existing implementation on the egress node can be leveraged for
measuring packet counts using the incoming SID (the PSID). 

For Passive performance measurement, path identification at the
measuring points is the pre-requisite. Path Segment can be used by the
measuring points (e.g., the ingress and egress nodes of the SR path or a
centralized controller) to correlate the packet counts and timestamps
from the ingress and egress nodes for a specific SR path, then packet
loss and delay can be calculated for the end-to-end path, respectively.

Path Segment can also be used for Active performance measurement for
an SR path in SR-MPLS networks for collecting packet counters and
timestamps from the egress node using probe messages.

Path Segment can also be used for In-situ OAM for SR-MPLS to identify
the SR Path associated with the in-situ data fields in the data packets
on the egress node.

Path Segment can also be used for In-band PM for SR-MPLS to identify
the SR Path associated with the collected performance metrics.


## Path Segment for Bidirectional SR Path {#psid-for-bpath}

In some scenarios, for example, mobile backhaul transport networks,
there are requirements to support bidirectional paths, and the path is
normally treated as a single entity. Forward and reverse directions of the path
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


## Path Segment for End-to-end Path Protection {#psid-for-protection}

For end-to-end 1+1 path protection (i.e., Live-Live case), the egress
node of the path needs to know the set of paths that constitute the
primary and the secondaries, in order to select the primary path packets
for onward transmission, and to discard the packets from the secondaries {{RFC4426}}.

To do this in Segment Routing, each SR path needs a path identifier
that is unique at the egress node. For SR-MPLS, this can be the Path
Segment label allocated by the egress node.

There then needs to be a method of binding this SR path identifiers
into equivalence groups such that the egress node can determine for
example, the set of packets that represent a single primary path. This equivalence group can be instantiated in the network
by an SDN controller using the Path Segments of the SR paths.


## Nesting of Path Segments {#psid-nesting}

Binding SID (BSID) {{RFC8402}} can be used for SID list
compression. With BSID, an end-to-end SR path can be split into several
sub-paths, each sub-path is identified by a BSID. Then an end-to-end SR
path can be identified by a list of BSIDs, therefore, it can provide
better scalability.

BSID and PSID can be combined to achieve both sub-path and
end-to-end path monitoring. A reference model for such a combination in
(Figure 2) shows an end-to-end path (A->D) that spans three domains
(Access, Aggregation and Core domain) and consists of three sub-paths,
one in each sub-domain (sub-path (A->B), sub-path (B->C) and
sub-path (C->D)). Each sub-path is associated with a BSID and a s-PSID. 

The SID list of the end-to-end path can be expressed as \<BSID1, BSID2, ..., BSIDn, e-PSID>, where the e-PSID is the PSID of the end-to-end path. The SID
list of a sub-path can be expressed as \<SID1, SID2, ...SIDn, s-PSID>, where the s-PSID is the PSID of the sub-path.

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


# Security Considerations {#Security}

A Path Segment in SR-MPLS is a label similar to other labels/Segment, such as a VPN label or a Prefix SID, defined in MPLS and SR-MPLS. The data plane processing of a PSID is a local implementation of an ingress node, or an egress node, which follows the same logic of existing MPLS dataplane.

A Path Segment is used within an SR-MPLS domain {{RFC8402}} and should not leak outside the domain, therefore no new security threats are introduced comparing to current SR-MPLS. The security consideration of SR-MPLS, such as boundary filtering described in {{Section 8.1 of RFC8402}} applies to this document. 

A PSID is allocated by an egress node and distributed to an ingress. The distribution is performed within an SR trusted domain. However, the mechanism of distributing a PSID is out of the scope of this document, and its security consideration will be described in other documents.


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

The following people have substantially contributed to this document.
