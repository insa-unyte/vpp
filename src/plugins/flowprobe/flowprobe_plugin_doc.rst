IPFIX flow record plugin
========================

Introduction
------------

This plugin generates ipfix flow records on interfaces which have the
feature enabled

Sample configuration
--------------------

::

  set ipfix exporter collector 192.168.6.2 src 192.168.6.1 template-interval 20 port 4739 path-mtu 1450

  flowprobe params record l3 active 20 passive 120
  flowprobe feature add-del GigabitEthernet2/3/0 l2


Monitoring SRv6 with On-path delay
-----------------------------------

SRv6 SRH as defined in RFC8754 can be exported with https://datatracker.ietf.org/doc/draft-ietf-opsawg-ipfix-srv6-srh/
Both srhSevmengIPv6BasicList and srhSegmentIPv6ListSection are implemented.

On-path delay can also be exported using IOAM as an on-path telemetry protocol.

Refer to https://github.com/network-analytics/vpp-srh-onpath-telemetry for more information.

Example for setting IPFIX exporter exporting the SRv6 SRH and the on-path delay.

::

  set ipfix exporter collector 10.11.4.1 src 13.13.13.13 template-interval 5

  flowprobe params record l3 active 5 passive 5
  flowprobe feature add-del memif2/0 srh-delay-listsection rx

Example for setting IPFIX exporter to export the SRv6 SRH only

::

  set ipfix exporter collector 10.11.4.1 src 22.22.22.22 template-interval 5

  flowprobe params record l3 active 5 passive 5
  flowprobe feature add-del memif1/0 srh-basiclist rx