/* Copyright 2020
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "config.h"
#include <epan/packet.h>

#define IPCP_ETH_DIX_ETHERTYPE 0xA000

/** function declaration */
static int dissect_ouroboros(tvbuff_t * tvb, packet_info * pinfo,
                             proto_tree * tree, void * p);

guint8 dissect_dt_pdu(proto_tree *, tvbuff_t *, guint, guint8, packet_info *,
                      proto_item *);

guint8 dissect_fa_pdu(proto_tree *, tvbuff_t *, guint, guint8, packet_info *,
                      proto_item *);

static int proto_ouroboros = -1;

/** sub trees */
static gint ett_ouroboros = -1;
static gint ett_ouroboros_dt = -1;
static gint ett_ouroboros_fa = -1;
static header_field_info *hf_ouroboros = NULL;

/** OUROBOROS protocol variables */
/** ipcpd-eth-dix */
static int hf_ouroboros_eth_eid = -1;
static int hf_ouroboros_eth_len = -1;
/** TODO? Dissect ipcpd-eth-dix flow allocator? */

/** ipcpd-unicast-dt */
static int hf_ouroboros_dt_addr = -1;
static int hf_ouroboros_dt_qc = -1;
static int hf_ouroboros_dt_ttl = -1;
static int hf_ouroboros_dt_ecn = -1;
static int hf_ouroboros_dt_eid = -1;

/** ipcpd-unicast-fa */
static int hf_ouroboros_fa_src = -1;
static int hf_ouroboros_fa_r_eid = -1;
static int hf_ouroboros_fa_s_eid = -1;
static int hf_ouroboros_fa_code = -1;
static int hf_ouroboros_fa_response = -1;
static int hf_ouroboros_fa_ece = -1;

/**  DHT PDU -> PROTOBUF, not dissecting that shit */

/** value_string structure is a way to map values to strings. */
static const value_string fa_codes[] = {
        {0, "FLOW REQUEST"},
        {1, "FLOW REPLY"},
        {2, "FLOW UPDATE"},
        {3, NULL}
};


void proto_register_ouroboros(void)
{
/** Field Registration */
        static hf_register_info hf[] = {
                /** For ouroboros */
                {&hf_ouroboros_eth_eid,
                 {"ipcpd-eth-dix eid", "ouroboros.eth_dix_eid",
                  FT_UINT16, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_eth_len,
                 {"ipcpd-eth-dix len", "ouroboros.eth_dix_len",
                  FT_UINT16, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_dt_addr,
                 {"Destination address", "ouroboros.unicast-dt-dst",
                  FT_UINT32, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_dt_qc,
                 {"QoS cube", "ouroboros.unicast-dt-qos",
                  FT_UINT8, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_dt_ttl,
                 {"Time-to-Live", "ouroboros.unicast-dt-ttl",
                  FT_UINT8, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_dt_ecn,
                 {"Explicit Congestion Notification", "ouroboros.unicast-dt-ecn",
                  FT_UINT8, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_dt_eid,
                 {"Endpoint ID", "ouroboros.unicast-dt-eid",
                  FT_UINT64, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_fa_src,
                 {"Source address", "ouroboros.unicast-fa-src",
                  FT_UINT64, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_fa_r_eid,
                 {"Remote endpint ID", "ouroboros.unicast-fa-r-eid",
                  FT_UINT64, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_fa_s_eid,
                 {"Source endpint ID", "ouroboros.unicast-fa-s-eid",
                  FT_UINT64, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_fa_code,
                 {"Flow allocator msg code", "ouroboros.unicast-fa-code",
                  FT_UINT8, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_fa_response,
                 {"Flow allocator response", "ouroboros.unicast-fa-code",
                  FT_INT8, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                },
                {&hf_ouroboros_fa_ece,
                 {"Explicit Congestion Experienced", "ouroboros.unicast-fa-ece",
                  FT_UINT16, BASE_DEC,
                  NULL, 0x0,
                  NULL, HFILL}
                }
        };

        /** Setup protocol subtree array */
        static gint *ett[] = {
                &ett_ouroboros,
                &ett_ouroboros_dt,
                &ett_ouroboros_fa
        };

        /** registering the myproto protocol with 3 names */
        proto_ouroboros = proto_register_protocol("OUROBOROS",
                                                  "ouroboros",
                                                  "ouroboros");

        hf_ouroboros = proto_registrar_get_nth(proto_ouroboros);

        /** Register header fields and subtrees. */
        proto_register_field_array(proto_ouroboros, hf, array_length(hf));

        /**  To register subtree types, pass an array of pointers */
        proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ouroboros(void)
{
        /** the handle for the dynamic dissector */
        dissector_handle_t ouroboros_handle;

        ouroboros_handle = create_dissector_handle(dissect_ouroboros,
                                                   proto_ouroboros);
        dissector_add_uint("ethertype", IPCP_ETH_DIX_ETHERTYPE,
                           ouroboros_handle);
}

static int dissect_ouroboros(tvbuff_t *    tvb,
                             packet_info * pinfo,
                             proto_tree *  tree,
                             void *        p)
{
        (void) p;
        /*col_set_str() function is used to set the column string */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "OUROBOROS");

        /*To clear corresponding column info */
        col_clear(pinfo->cinfo, COL_INFO);

        if (tree) {
                proto_item * ti;
                proto_tree * ouroboros_tree;
                guint8 offset = 0;
                guint8 eid;

                /** Adding Items and Values to the Protocol Tree */
                ti = proto_tree_add_item(tree, proto_ouroboros, tvb, 0, -1,
                                         FALSE);
                ouroboros_tree = proto_item_add_subtree(ti, ett_ouroboros);

                /** adding each item to ouroboros */
                eid = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) == 0 ? 0 : 1;
                proto_tree_add_item(ouroboros_tree, hf_ouroboros_eth_eid, tvb,
                                    offset, 2, FALSE);
                offset += 2;

                proto_tree_add_item(ouroboros_tree, hf_ouroboros_eth_len, tvb,
                                    offset, 2, FALSE);

                offset += 2;

                offset = dissect_dt_pdu(ouroboros_tree, tvb, offset,
                                        eid, pinfo, ti);
        }

        return 0;
}

guint8 dissect_dt_pdu(proto_tree * ouroboros_tree, tvbuff_t * tvb, guint offset,
                      guint8 eid, packet_info * pinfo, proto_item * ti)
{
        proto_tree * dt_tree;

        if (eid == 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s ",
                                "ETH flow allocator (0x%02x)");
        } else {
                dt_tree = proto_item_add_subtree(ouroboros_tree,
                                                 ett_ouroboros_dt);

                ti = proto_tree_add_item(dt_tree, hf_ouroboros_dt_addr,
                                         tvb, offset, 4, FALSE);

                offset += 4;

                proto_tree_add_item(dt_tree, hf_ouroboros_dt_qc,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                proto_tree_add_item(dt_tree, hf_ouroboros_dt_ttl,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                proto_tree_add_item(dt_tree, hf_ouroboros_dt_ecn,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                eid = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN) == 0 ? 0 : 1;
                proto_tree_add_item(dt_tree, hf_ouroboros_dt_eid,
                                    tvb, offset, 8, FALSE);
                offset += 8;

                offset = dissect_fa_pdu(dt_tree, tvb, offset,
                                        eid, pinfo, ti);
        }

        return offset;
}

guint8 dissect_fa_pdu(proto_tree * ouroboros_tree, tvbuff_t * tvb, guint offset,
                      guint8 eid, packet_info * pinfo, proto_item * ti)
{
        proto_tree * fa_tree;
        guint8       code;

        if (eid != 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "N+1 Data");
        } else {
                fa_tree = proto_item_add_subtree(ouroboros_tree,
                                                 ett_ouroboros_fa);

                proto_tree_add_item(fa_tree, hf_ouroboros_fa_src,
                                    tvb, offset, 8, FALSE);
                offset += 8;

                proto_tree_add_item(fa_tree, hf_ouroboros_fa_r_eid,
                                    tvb, offset, 8, FALSE);
                offset += 8;

                proto_tree_add_item(fa_tree, hf_ouroboros_fa_s_eid,
                                    tvb, offset, 8, FALSE);
                offset += 8;

                code = tvb_get_guint8(tvb, offset);

                ti = proto_tree_add_item(fa_tree, hf_ouroboros_fa_code,
                                    tvb, offset, 1, FALSE);

                col_append_fstr(pinfo->cinfo, COL_INFO, " %s ",
                                val_to_str(code, fa_codes,
                                           "Unknown (0x%02x)"));

                proto_item_append_text(ti, " FA Type: %s",
                                       val_to_str(code, fa_codes,
                                                  "Unknown (0x%02x)"));
                offset += 1;

                proto_tree_add_item(fa_tree, hf_ouroboros_fa_response,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                proto_tree_add_item(fa_tree, hf_ouroboros_fa_ece,
                                    tvb, offset, 2, FALSE);
                offset += 2;
        }

        return offset;
}
