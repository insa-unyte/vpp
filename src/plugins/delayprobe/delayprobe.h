/*
 * delayprobe.h - ipfix probe plug-in header file
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __included_delayprobe_h__
#define __included_delayprobe_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/ipfix-export/flow_report_classify.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

/* Default timers in seconds */
#define delayprobe_TIMER_ACTIVE	 (15)
#define delayprobe_TIMER_PASSIVE 120 // XXXX: FOR TESTING (30*60)
#define delayprobe_LOG2_HASHSIZE (18)

typedef enum
{
  FLOW_RECORD_L3 = 1 << 0,
  FLOW_N_RECORDS = 1 << 1,
  // FLOW_RECORD_L2 = 1 << 0,
  // FLOW_RECORD_L4 = 1 << 2,
  // FLOW_RECORD_L2_IP4 = 1 << 3,
  // FLOW_RECORD_L2_IP6 = 1 << 4,
} delayprobe_record_t;

/* *INDENT-OFF* */
typedef enum __attribute__ ((__packed__))
{
  FLOW_VARIANT_SRH_IP6 = 0,
  FLOW_N_VARIANTS,
  // FLOW_VARIANT_IP6,
  // FLOW_VARIANT_L2,
  // FLOW_VARIANT_L2_IP4,
  // FLOW_VARIANT_L2_IP6,
  // FLOW_VARIANT_SRH_IP6,
} delayprobe_variant_t;

typedef enum __attribute__ ((__packed__))
{
  FLOW_DIRECTION_RX = 0,
  FLOW_DIRECTION_TX,
  FLOW_DIRECTION_BOTH,
} delayprobe_direction_t;
/* *INDENT-ON* */

STATIC_ASSERT (sizeof (delayprobe_variant_t) == 1,
	       "delayprobe_variant_t is expected to be 1 byte, "
	       "revisit padding in delayprobe_key_t");

#define FLOW_MAXIMUM_EXPORT_ENTRIES (1024)
#define FLOW_SRH_MAX_SID_LIST	    (8)

typedef struct
{
  /* what to collect per variant */
  delayprobe_record_t flags;
  /** ipfix buffers under construction, per-worker thread */
  vlib_buffer_t **buffers_per_worker;
  /** frames containing ipfix buffers, per-worker thread */
  vlib_frame_t **frames_per_worker;
  /** next record offset, per worker thread */
  u16 *next_record_offset_per_worker;
} delayprobe_protocol_context_t;

/* *INDENT-OFF* */
typedef struct __attribute__ ((aligned (8)))
{
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  u8 src_mac[6];
  u8 dst_mac[6];
  u16 ethertype;
  ip46_address_t src_address;
  ip46_address_t dst_address;
  u8 protocol;
  u16 src_port;
  u16 dst_port;
  delayprobe_variant_t which;
  delayprobe_direction_t direction;

  ip46_address_t srh_src_address;
  ip46_address_t srh_dst_address;
  u8 srh_segments_left;
  u8 srh_flags;
  u16 srh_tag;
  ip46_address_t srh_segment_list[FLOW_SRH_MAX_SID_LIST];
} delayprobe_key_t;
/* *INDENT-ON* */

typedef struct
{
  u32 sec;
  u32 nsec;
} timestamp_nsec_t;

typedef struct
{
  delayprobe_key_t key;
  u64 packetcount;
  u64 octetcount;
  timestamp_nsec_t flow_start;
  timestamp_nsec_t flow_end;
  f64 last_updated;
  f64 last_exported;
  u32 passive_timer_handle;
  u16 srh_endpoint_behavior;
  union
  {
    struct
    {
      u16 flags;
    } tcp;
  } prot;
} delayprobe_entry_t;

/**
 * @file
 * @brief flow-per-packet plugin header file
 */
typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  delayprobe_protocol_context_t context[FLOW_N_VARIANTS];
  u16 template_reports[FLOW_N_RECORDS];
  u16 template_size[FLOW_N_RECORDS];

  /** Time reference pair */
  u64 nanosecond_time_0;
  f64 vlib_time_0;

  /** Per CPU flow-state */
  u8 ht_log2len; /* Hash table size is 2^log2len */
  u32 **hash_per_worker;
  delayprobe_entry_t **pool_per_worker;
  /* *INDENT-OFF* */
  TWT (tw_timer_wheel) * *timers_per_worker;
  /* *INDENT-ON* */
  u32 **expired_passive_per_worker;

  delayprobe_record_t record;
  u32 active_timer;
  u32 passive_timer;
  delayprobe_entry_t *stateless_entry;

  bool initialized;
  bool disabled;

  u16 template_per_flow[FLOW_N_VARIANTS];
  u8 *flow_per_interface;
  u8 *direction_per_interface;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} delayprobe_main_t;

extern delayprobe_main_t delayprobe_main;
extern vlib_node_registration_t delayprobe_walker_node;

void delayprobe_flush_callback_srh_ip6 (void);
u8 *format_delayprobe_entry (u8 *s, va_list *args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
