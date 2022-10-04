/*
 * node.c - ipfix probe graph node
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/crc32.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/error.h>
#include <delayprobe/delayprobe.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_local.h>
#include <vlibmemory/api.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/srv6/sr.h>

static void delayprobe_export_entry (vlib_main_t *vm, delayprobe_entry_t *e);

/**
 * @file node.c
 * flow record generator graph node
 */

typedef struct
{
  /** interface handle */
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  /** packet timestamp */
  u64 timestamp;
  /** size of the buffer */
  u16 buffer_size;

  /** L2 information */
  u8 src_mac[6];
  u8 dst_mac[6];
  /** Ethertype */
  u16 ethertype;

  /** L3 information */
  ip46_address_t src_address;
  ip46_address_t dst_address;
  u8 protocol;
  u8 tos;

  /** L4 information */
  u16 src_port;
  u16 dst_port;

  delayprobe_variant_t which;
} delayprobe_trace_t;

static char *delayprobe_variant_strings[] = {
  [FLOW_VARIANT_SRH_IP6] = "IP6_SRH",
};

/* packet trace format function */
static u8 *
format_delayprobe_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  delayprobe_trace_t *t = va_arg (*args, delayprobe_trace_t *);
  // u32 indent = format_get_indent (s);

  s = format (s,
	      "delayprobe[%s]: rx_sw_if_index %d, tx_sw_if_index %d, "
	      "timestamp %lld, size %d",
	      delayprobe_variant_strings[t->which], t->rx_sw_if_index,
	      t->tx_sw_if_index, t->timestamp, t->buffer_size);

  // if (t->protocol > 0 &&
  //     (t->which == FLOW_VARIANT_L2_IP4 || t->which == FLOW_VARIANT_IP4 ||
  //      t->which == FLOW_VARIANT_L2_IP6 || t->which == FLOW_VARIANT_IP6))
  //   s = format (s, "\n%U%U: %U -> %U", format_white_space, indent,
  // 	format_ip_protocol, t->protocol, format_ip46_address,
  // 	&t->src_address, IP46_TYPE_ANY, format_ip46_address,
  // 	&t->dst_address, IP46_TYPE_ANY);
  return s;
}

vlib_node_registration_t delayprobe_input_ip4_node;
vlib_node_registration_t delayprobe_input_ip6_node;
vlib_node_registration_t delayprobe_input_l2_node;
vlib_node_registration_t delayprobe_output_ip4_node;
vlib_node_registration_t delayprobe_output_ip6_node;
vlib_node_registration_t delayprobe_output_l2_node;

/* No counters at the moment */
#define foreach_delayprobe_error                                              \
  _ (COLLISION, "Hash table collisions")                                      \
  _ (BUFFER, "Buffer allocation error")                                       \
  _ (EXPORTED_PACKETS, "Exported packets")                                    \
  _ (INPATH, "Exported packets in path")

typedef enum
{
#define _(sym, str) delayprobe_ERROR_##sym,
  foreach_delayprobe_error
#undef _
    delayprobe_N_ERROR,
} delayprobe_error_t;

static char *delayprobe_error_strings[] = {
#define _(sym, string) string,
  foreach_delayprobe_error
#undef _
};

typedef enum
{
  DELAYPROBE_NEXT_DROP,
  DELAYPROBE_NEXT_IP4_LOOKUP,
  DELAYPROBE_N_NEXT,
} delayprobe_next_t;

#define DELAYPROBE_NEXT_NODES                                                 \
  {                                                                           \
    [DELAYPROBE_NEXT_DROP] = "error-drop",                                    \
    [DELAYPROBE_NEXT_IP4_LOOKUP] = "ip4-lookup",                              \
  }

#define DELAYPROBE6_NEXT_NODES                                                \
  {                                                                           \
    [DELAYPROBE_NEXT_DROP] = "error-drop",                                    \
    [DELAYPROBE_NEXT_IP4_LOOKUP] = "ip6-lookup",                              \
  }

static inline delayprobe_variant_t
delayprobe_get_variant (delayprobe_variant_t which, delayprobe_record_t flags,
			u16 ethertype)
{
  // if (which == FLOW_VARIANT_L2 &&
  //     (flags & FLOW_RECORD_L3 || flags & FLOW_RECORD_L4))
  //   return ethertype == ETHERNET_TYPE_IP6 ? FLOW_VARIANT_L2_IP6 :
  //    ethertype == ETHERNET_TYPE_IP4 ? FLOW_VARIANT_L2_IP4 :
  // 				    FLOW_VARIANT_L2;
  return which;
}

/*
 * NTP rfc868 : 2 208 988 800 corresponds to 00:00  1 Jan 1970 GMT
 */
#define NTP_TIMESTAMP 2208988800LU

static inline u32
delayprobe_srh_ip6_add (vlib_buffer_t *to_b, delayprobe_entry_t *e, u16 offset)
{
  u16 start = offset;

  /* flow src address */
  clib_memcpy_fast (to_b->data + offset, &e->key.src_address,
		    sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* flow dst address */
  clib_memcpy_fast (to_b->data + offset, &e->key.dst_address,
		    sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* Flow direction
     0x00: ingress flow
     0x01: egress flow */
  to_b->data[offset++] = (e->key.direction == FLOW_DIRECTION_TX);

  /* packet delta count */
  u64 packetdelta = clib_host_to_net_u64 (e->packetcount);
  clib_memcpy_fast (to_b->data + offset, &packetdelta, sizeof (u64));
  offset += sizeof (u64);

  /* octetDeltaCount */
  u64 octetdelta = clib_host_to_net_u64 (e->octetcount);
  clib_memcpy_fast (to_b->data + offset, &octetdelta, sizeof (u64));
  offset += sizeof (u64);

  return offset - start;
}

static inline u32
delayprobe_hash (delayprobe_key_t *k)
{
  delayprobe_main_t *fm = &delayprobe_main;
  u32 h = 0;

#ifdef clib_crc32c_uses_intrinsics
  h = clib_crc32c ((u8 *) k, sizeof (*k));
#else
  int i;
  u64 tmp = 0;
  for (i = 0; i < sizeof (*k) / 8; i++)
    tmp ^= ((u64 *) k)[i];

  h = clib_xxhash (tmp);
#endif

  return h >> (32 - fm->ht_log2len);
}

delayprobe_entry_t *
delayprobe_lookup (u32 my_cpu_number, delayprobe_key_t *k, u32 *poolindex,
		   bool *collision)
{
  delayprobe_main_t *fm = &delayprobe_main;
  delayprobe_entry_t *e;
  u32 h;

  h = (fm->active_timer) ? delayprobe_hash (k) : 0;

  /* Lookup in the flow state pool */
  *poolindex = fm->hash_per_worker[my_cpu_number][h];
  if (*poolindex != ~0)
    {
      e = pool_elt_at_index (fm->pool_per_worker[my_cpu_number], *poolindex);
      if (e)
	{
	  /* Verify key or report collision */
	  if (memcmp (k, &e->key, sizeof (delayprobe_key_t)))
	    *collision = true;
	  return e;
	}
    }

  return 0;
}

delayprobe_entry_t *
delayprobe_create (u32 my_cpu_number, delayprobe_key_t *k, u32 *poolindex)
{
  delayprobe_main_t *fm = &delayprobe_main;
  u32 h;

  delayprobe_entry_t *e;

  /* Get my index */
  h = (fm->active_timer) ? delayprobe_hash (k) : 0;

  pool_get (fm->pool_per_worker[my_cpu_number], e);
  *poolindex = e - fm->pool_per_worker[my_cpu_number];
  fm->hash_per_worker[my_cpu_number][h] = *poolindex;

  e->key = *k;

  if (fm->passive_timer > 0)
    {
      e->passive_timer_handle =
	tw_timer_start_2t_1w_2048sl (fm->timers_per_worker[my_cpu_number],
				     *poolindex, 0, fm->passive_timer);
    }
  return e;
}

static inline void
add_to_flow_record_state (vlib_main_t *vm, vlib_node_runtime_t *node,
			  delayprobe_main_t *fm, vlib_buffer_t *b,
			  timestamp_nsec_t timestamp, u16 length,
			  delayprobe_variant_t which,
			  delayprobe_direction_t direction,
			  delayprobe_trace_t *t)
{
  if (fm->disabled)
    return;

  ASSERT (direction == FLOW_DIRECTION_RX || direction == FLOW_DIRECTION_TX);

  u32 my_cpu_number = vm->thread_index;
  u16 octets = 0;
  u16 active_sid_behavior = 0;

  delayprobe_record_t flags = fm->context[which].flags;
  // bool collect_ip4 = false, collect_ip6 = false, collect_srh = false;
  ASSERT (b);
  ethernet_header_t *eth = ethernet_buffer_get_header (b);
  // ethernet_header_t *eh0 = vlib_buffer_get_current (b);
  u16 ethertype = clib_net_to_host_u16 (eth->type);
  // u16 ethertype_bis = clib_net_to_host_u16 (eh0->type);
  // clib_warning ("add_to_flow_record_state! ethertype: %X - %X | %x",
  // ethertype, ethertype_bis, eth->type); ip6_header_t *ip6_test =
  // vlib_buffer_get_current(b); clib_warning("MAC--> %U->%U",
  // format_ethernet_address, &eh0->src_address, format_ethernet_address,
  // &eh0->dst_address); clib_warning("MAC--> %U->%U", format_ethernet_address,
  // &eth->src_address, format_ethernet_address, &eth->dst_address);
  // clib_warning("IPv6--> %U->%U", format_ip6_address, &ip6_test->src_address,
  // format_ip6_address, &ip6_test->dst_address);

  u16 l2_hdr_sz = sizeof (ethernet_header_t);
  /* *INDENT-OFF* */
  delayprobe_key_t k = {};
  /* *INDENT-ON* */
  // ip4_header_t *ip4 = 0;
  ip6_header_t *ip6 = 0;
  udp_header_t *udp = 0;
  tcp_header_t *tcp = 0;
  u8 tcp_flags = 0;

  k.rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  k.tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];

  k.which = which;
  k.direction = direction;

  if (ethertype == ETHERNET_TYPE_VLAN)
    {
      /*VLAN TAG*/
      ethernet_vlan_header_tv_t *ethv =
	(ethernet_vlan_header_tv_t *) (&(eth->type));
      /*Q in Q possibility */
      while (clib_net_to_host_u16 (ethv->type) == ETHERNET_TYPE_VLAN)
	{
	  ethv++;
	  l2_hdr_sz += sizeof (ethernet_vlan_header_tv_t);
	}
      k.ethertype = ethertype = clib_net_to_host_u16 ((ethv)->type);
    }

  if (ethertype == ETHERNET_TYPE_IP6)
    {
      ip6 = (ip6_header_t *) (b->data + l2_hdr_sz);
      if (flags & FLOW_RECORD_L3)
	{
	  k.src_address.as_u64[0] = ip6->src_address.as_u64[0];
	  k.src_address.as_u64[1] = ip6->src_address.as_u64[1];
	  k.dst_address.as_u64[0] = ip6->dst_address.as_u64[0];
	  k.dst_address.as_u64[1] = ip6->dst_address.as_u64[1];
	}
      k.protocol = ip6->protocol;
      if (k.protocol == IP_PROTOCOL_UDP)
	udp = (udp_header_t *) (ip6 + 1);
      else if (k.protocol == IP_PROTOCOL_TCP)
	tcp = (tcp_header_t *) (ip6 + 1);

      octets =
	clib_net_to_host_u16 (ip6->payload_length) + sizeof (ip6_header_t);

      if (direction == FLOW_DIRECTION_TX && udp)
	{
	  clib_warning ("Is TX, modify packet!");
	  ip6_hop_by_hop_header_t *hbh;
	  u8 *rewrite = NULL;
	  u32 size, rnd_size;
	  u8 *current;
    u16 new_length;

	  // u16 ip6_payload_length;

	  size = sizeof (ip6_hop_by_hop_header_t) + 16; // header + 64 bits
	  rnd_size = (size + 7) & ~7;
	  vec_validate (rewrite, rnd_size - 1);
    u32 rewrite_length = vec_len (rewrite);

	  vlib_buffer_advance (b, -(word) rewrite_length);

	  hbh = (ip6_hop_by_hop_header_t *) (ip6 + 1);

	  /* Length of header in 8 octet units, not incl first 8 octets */
	  hbh->length = (rnd_size >> 3) - 1;
	  current = (u8 *) (hbh + 1);

    clib_warning("Next IP: %u", ip6->protocol);
    new_length = clib_net_to_host_u16 (ip6->payload_length) + (hbh->length);
    // clib_warning("Next IP: %u", ip6->protocol);
	  hbh->protocol = ip6->protocol;
	  ip6->payload_length = clib_host_to_net_u16(new_length);
    // hbh->length = 16;
    clib_warning("Next HBH: %u", hbh->protocol);
	  ip6->protocol = 0; // hop-by-hop ext option

    // udp = (udp_header_t *) (hbh + 1);
	}
    }

  if (udp)
    {
      k.src_port = udp->src_port;
      k.dst_port = udp->dst_port;
    }
  else if (tcp)
    {
      k.src_port = tcp->src_port;
      k.dst_port = tcp->dst_port;
      tcp_flags = tcp->flags;
    }

  if (t)
    {
      t->rx_sw_if_index = k.rx_sw_if_index;
      t->tx_sw_if_index = k.tx_sw_if_index;
      clib_memcpy_fast (t->src_mac, k.src_mac, 6);
      clib_memcpy_fast (t->dst_mac, k.dst_mac, 6);
      t->ethertype = k.ethertype;
      t->src_address.ip4.as_u32 = k.src_address.ip4.as_u32;
      t->dst_address.ip4.as_u32 = k.dst_address.ip4.as_u32;
      t->protocol = k.protocol;
      t->src_port = k.src_port;
      t->dst_port = k.dst_port;
      t->which = k.which;
    }

  delayprobe_entry_t *e = 0;
  f64 now = vlib_time_now (vm);
  if (fm->active_timer > 0)
    {
      u32 poolindex = ~0;
      bool collision = false;

      e = delayprobe_lookup (my_cpu_number, &k, &poolindex, &collision);
      if (collision)
	{
	  /* Flush data and clean up entry for reuse. */
	  if (e->packetcount)
	    delayprobe_export_entry (vm, e);
	  e->key = k;
	  e->flow_start = timestamp;
	  vlib_node_increment_counter (vm, node->node_index,
				       delayprobe_ERROR_COLLISION, 1);
	}
      if (!e) /* Create new entry */
	{
	  e = delayprobe_create (my_cpu_number, &k, &poolindex);
	  e->last_exported = now;
	  e->flow_start = timestamp;
	}
    }
  else
    {
      e = &fm->stateless_entry[my_cpu_number];
      e->key = k;
    }

  if (e)
    {
      /* Updating entry */
      e->packetcount++;
      e->octetcount += octets;
      e->last_updated = now;
      e->flow_end = timestamp;
      e->prot.tcp.flags |= tcp_flags;
      e->srh_endpoint_behavior = active_sid_behavior;
      if (fm->active_timer == 0 || (now > e->last_exported + fm->active_timer))
	delayprobe_export_entry (vm, e);
    }
}

static u16
delayprobe_get_headersize (void)
{
  return sizeof (ip4_header_t) + sizeof (udp_header_t) +
	 sizeof (ipfix_message_header_t) + sizeof (ipfix_set_header_t);
}

static void
delayprobe_export_send (vlib_main_t *vm, vlib_buffer_t *b0,
			delayprobe_variant_t which)
{
  delayprobe_main_t *fm = &delayprobe_main;
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp = pool_elt_at_index (frm->exporters, 0);
  vlib_frame_t *f;
  ip4_ipfix_template_packet_t *tp;
  ipfix_set_header_t *s;
  ipfix_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  delayprobe_record_t flags = fm->context[which].flags;
  u32 my_cpu_number = vm->thread_index;

  /* Fill in header */
  flow_report_stream_t *stream;
  // clib_warning("export send %d", delayprobe_get_headersize ());
  /* Nothing to send */
  if (fm->context[which].next_record_offset_per_worker[my_cpu_number] <=
      delayprobe_get_headersize ())
    return;

  u32 i, index = vec_len (exp->streams);
  for (i = 0; i < index; i++)
    if (exp->streams[i].domain_id == 1)
      {
	index = i;
	break;
      }
  if (i == vec_len (exp->streams))
    {
      vec_validate (exp->streams, index);
      exp->streams[index].domain_id = 1;
    }
  stream = &exp->streams[index];

  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->flags_and_fragment_offset = 0;
  ip->src_address.as_u32 = exp->src_address.ip.ip4.as_u32;
  ip->dst_address.as_u32 = exp->ipfix_collector.ip.ip4.as_u32;
  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (exp->collector_port);
  udp->checksum = 0;

  /* FIXUP: message header export_time */
  h->export_time = (u32) (((f64) frm->unix_time_0) +
			  (vlib_time_now (frm->vlib_main) - frm->vlib_time_0));
  h->export_time = clib_host_to_net_u32 (h->export_time);
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* FIXUP: message header sequence_number */
  h->sequence_number = stream->sequence_number++;
  h->sequence_number = clib_host_to_net_u32 (h->sequence_number);

  s->set_id_length = ipfix_set_id_length (
    fm->template_reports[flags],
    b0->current_length - (sizeof (*ip) + sizeof (*udp) + sizeof (*h)));
  h->version_length =
    version_length (b0->current_length - (sizeof (*ip) + sizeof (*udp)));

  ip->length = clib_host_to_net_u16 (b0->current_length);

  ip->checksum = ip4_header_checksum (ip);
  udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

  if (exp->udp_checksum)
    {
      /* RFC 7011 section 10.3.2. */
      udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
      if (udp->checksum == 0)
	udp->checksum = 0xffff;
    }

  ASSERT (ip4_header_checksum_is_valid (ip));

  /* Find or allocate a frame */
  f = fm->context[which].frames_per_worker[my_cpu_number];
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      fm->context[which].frames_per_worker[my_cpu_number] = f;
      u32 bi0 = vlib_get_buffer_index (vm, b0);

      /* Enqueue the buffer */
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
  vlib_node_increment_counter (vm, delayprobe_output_l2_node.index,
			       delayprobe_ERROR_EXPORTED_PACKETS, 1);

  fm->context[which].frames_per_worker[my_cpu_number] = 0;
  fm->context[which].buffers_per_worker[my_cpu_number] = 0;
  fm->context[which].next_record_offset_per_worker[my_cpu_number] =
    delayprobe_get_headersize ();
}

static vlib_buffer_t *
delayprobe_get_buffer (vlib_main_t *vm, delayprobe_variant_t which)
{
  delayprobe_main_t *fm = &delayprobe_main;
  ipfix_exporter_t *exp = pool_elt_at_index (flow_report_main.exporters, 0);
  vlib_buffer_t *b0;
  u32 bi0;
  u32 my_cpu_number = vm->thread_index;

  /* Find or allocate a buffer */
  b0 = fm->context[which].buffers_per_worker[my_cpu_number];

  /* Need to allocate a buffer? */
  if (PREDICT_FALSE (b0 == 0))
    {
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  vlib_node_increment_counter (vm, delayprobe_output_l2_node.index,
				       delayprobe_ERROR_BUFFER, 1);
	  return 0;
	}

      /* Initialize the buffer */
      b0 = fm->context[which].buffers_per_worker[my_cpu_number] =
	vlib_get_buffer (vm, bi0);

      b0->current_data = 0;
      b0->current_length = delayprobe_get_headersize ();
      b0->flags |=
	(VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = exp->fib_index;
      fm->context[which].next_record_offset_per_worker[my_cpu_number] =
	b0->current_length;
    }

  return b0;
}

static void
delayprobe_export_entry (vlib_main_t *vm, delayprobe_entry_t *e)
{
  u32 my_cpu_number = vm->thread_index;
  delayprobe_main_t *fm = &delayprobe_main;
  ipfix_exporter_t *exp = pool_elt_at_index (flow_report_main.exporters, 0);
  vlib_buffer_t *b0;
  bool collect_srh = false;
  delayprobe_variant_t which = e->key.which;
  delayprobe_record_t flags = fm->context[which].flags;
  u16 offset = fm->context[which].next_record_offset_per_worker[my_cpu_number];

  if (offset < delayprobe_get_headersize ())
    offset = delayprobe_get_headersize ();

  b0 = delayprobe_get_buffer (vm, which);
  /* No available buffer, what to do... */
  if (b0 == 0)
    return;

  if (flags & FLOW_RECORD_L3)
    {
      // collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which ==
      // FLOW_VARIANT_IP4; collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which
      // == FLOW_VARIANT_IP6;
      collect_srh = which == FLOW_VARIANT_SRH_IP6;
    }

  offset += delayprobe_srh_ip6_add (b0, e, offset);

  /* Reset per flow-export counters */
  e->packetcount = 0;
  e->octetcount = 0;
  e->last_exported = vlib_time_now (vm);

  b0->current_length = offset;

  fm->context[which].next_record_offset_per_worker[my_cpu_number] = offset;
  /* Time to flush the buffer? */
  if (offset + fm->template_size[flags] > exp->path_mtu)
    delayprobe_export_send (vm, b0, which);
}

uword
delayprobe_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, delayprobe_variant_t which,
		    delayprobe_direction_t direction)
{
  u32 n_left_from, *from, *to_next;
  delayprobe_next_t next_index;
  delayprobe_main_t *fm = &delayprobe_main;
  timestamp_nsec_t timestamp;
  unix_time_now_nsec_fraction (&timestamp.sec, &timestamp.nsec);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = DELAYPROBE_NEXT_DROP;
	  u32 next1 = DELAYPROBE_NEXT_DROP;
	  u16 len0, len1;
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    clib_prefetch_store (p2->data);
	    clib_prefetch_store (p3->data);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);

	  if (PREDICT_TRUE ((b0->flags & VNET_BUFFER_F_FLOW_REPORT) == 0))
	    add_to_flow_record_state (
	      vm, node, fm, b0, timestamp, len0,
	      delayprobe_get_variant (which, fm->context[which].flags,
				      ethertype0),
	      direction, 0);

	  len1 = vlib_buffer_length_in_chain (vm, b1);
	  ethernet_header_t *eh1 = vlib_buffer_get_current (b1);
	  u16 ethertype1 = clib_net_to_host_u16 (eh1->type);

	  if (PREDICT_TRUE ((b1->flags & VNET_BUFFER_F_FLOW_REPORT) == 0))
	    add_to_flow_record_state (
	      vm, node, fm, b1, timestamp, len1,
	      delayprobe_get_variant (which, fm->context[which].flags,
				      ethertype1),
	      direction, 0);

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = DELAYPROBE_NEXT_DROP;
	  u16 len0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vnet_feature_next (&next0, b0);

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);

	  if (PREDICT_TRUE ((b0->flags & VNET_BUFFER_F_FLOW_REPORT) == 0))
	    {
	      delayprobe_trace_t *t = 0;
	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
				 (b0->flags & VLIB_BUFFER_IS_TRACED)))
		t = vlib_add_trace (vm, node, b0, sizeof (*t));

	      add_to_flow_record_state (
		vm, node, fm, b0, timestamp, len0,
		delayprobe_get_variant (which, fm->context[which].flags,
					ethertype0),
		direction, t);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

static uword
delayprobe_input_srh_ip6_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
				  vlib_frame_t *frame)
{
  return delayprobe_node_fn (vm, node, frame, FLOW_VARIANT_SRH_IP6,
			     FLOW_DIRECTION_RX);
}

static uword
delayprobe_output_srh_ip6_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
				   vlib_frame_t *frame)
{
  return delayprobe_node_fn (vm, node, frame, FLOW_VARIANT_SRH_IP6,
			     FLOW_DIRECTION_TX);
}

static inline void
flush_record (delayprobe_variant_t which)
{
  vlib_main_t *vm = vlib_get_main ();
  // clib_warning("flushing %d", which == FLOW_VARIANT_SRH_IP6);
  vlib_buffer_t *b = delayprobe_get_buffer (vm, which);
  if (b)
    delayprobe_export_send (vm, b, which);
}

void
delayprobe_flush_callback_srh_ip6 (void)
{
  flush_record (FLOW_VARIANT_SRH_IP6);
}

static void
delayprobe_delete_by_index (u32 my_cpu_number, u32 poolindex)
{
  delayprobe_main_t *fm = &delayprobe_main;
  delayprobe_entry_t *e;
  u32 h;

  e = pool_elt_at_index (fm->pool_per_worker[my_cpu_number], poolindex);

  /* Get my index */
  h = delayprobe_hash (&e->key);

  /* Reset hash */
  fm->hash_per_worker[my_cpu_number][h] = ~0;

  pool_put_index (fm->pool_per_worker[my_cpu_number], poolindex);
}

/* Per worker process processing the active/passive expired entries */
static uword
delayprobe_walker_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
			   vlib_frame_t *f)
{
  delayprobe_main_t *fm = &delayprobe_main;
  delayprobe_entry_t *e;
  ipfix_exporter_t *exp = pool_elt_at_index (flow_report_main.exporters, 0);

  /*
   * $$$$ Remove this check from here and track FRM status and disable
   * this process if required.
   */
  if (ip_address_is_zero (&exp->ipfix_collector) ||
      ip_address_is_zero (&exp->src_address))
    {
      fm->disabled = true;
      return 0;
    }
  fm->disabled = false;

  u32 cpu_index = os_get_thread_index ();
  u32 *to_be_removed = 0, *i;

  /*
   * Tick the timer when required and process the vector of expired
   * timers
   */
  f64 start_time = vlib_time_now (vm);
  u32 count = 0;

  tw_timer_expire_timers_2t_1w_2048sl (fm->timers_per_worker[cpu_index],
				       start_time);

  vec_foreach (i, fm->expired_passive_per_worker[cpu_index])
    {
      u32 exported = 0;
      f64 now = vlib_time_now (vm);
      if (now > start_time + 100e-6 ||
	  exported > FLOW_MAXIMUM_EXPORT_ENTRIES - 1)
	break;

      if (pool_is_free_index (fm->pool_per_worker[cpu_index], *i))
	{
	  clib_warning ("Element is %d is freed already\n", *i);
	  continue;
	}
      else
	e = pool_elt_at_index (fm->pool_per_worker[cpu_index], *i);

      /* Check last update timestamp. If it is longer than passive time nuke
       * entry. Otherwise restart timer with what's left
       * Premature passive timer by more than 10%
       */
      if ((now - e->last_updated) < (u64) (fm->passive_timer * 0.9))
	{
	  u64 delta = fm->passive_timer - (now - e->last_updated);
	  e->passive_timer_handle = tw_timer_start_2t_1w_2048sl (
	    fm->timers_per_worker[cpu_index], *i, 0, delta);
	}
      else /* Nuke entry */
	{
	  vec_add1 (to_be_removed, *i);
	}
      /* If anything to report send it to the exporter */
      if (e->packetcount && now > e->last_exported + fm->active_timer)
	{
	  exported++;
	  delayprobe_export_entry (vm, e);
	}
      count++;
    }
  if (count)
    vec_delete (fm->expired_passive_per_worker[cpu_index], count, 0);

  vec_foreach (i, to_be_removed)
    delayprobe_delete_by_index (cpu_index, *i);
  vec_free (to_be_removed);

  return 0;
}

VLIB_REGISTER_NODE (delayprobe_input_srh_ip6_node) = {
  .function = delayprobe_input_srh_ip6_node_fn,
  .name = "delayprobe-input-srh-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_delayprobe_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (delayprobe_error_strings),
  .error_strings = delayprobe_error_strings,
  .n_next_nodes = DELAYPROBE_N_NEXT,
  .next_nodes = DELAYPROBE6_NEXT_NODES,
};

VLIB_REGISTER_NODE (flowprobe_output_ip6_node) = {
  .function = delayprobe_output_srh_ip6_node_fn,
  .name = "delayprobe-output-srh-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_delayprobe_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (delayprobe_error_strings),
  .error_strings = delayprobe_error_strings,
  .n_next_nodes = DELAYPROBE_N_NEXT,
  .next_nodes = DELAYPROBE6_NEXT_NODES,
};

VLIB_REGISTER_NODE (delayprobe_walker_node) = {
  .function = delayprobe_walker_process,
  .name = "delayprobe-walker",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
