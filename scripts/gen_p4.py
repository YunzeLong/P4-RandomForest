#!/usr/bin/env python3

import sys
import json
from json.decoder import JSONDecodeError
from argparse import ArgumentParser

config_base_tmpl = {
    'target': 'bmv2',
    'p4info': 'build/rfroute.p4.p4info.txt',
    'bmv2_json': 'build/rfroute.json',
    'table_entries': []
}
config_table_common = {
    'table': 'RFIngress.rf_tree_%d_%d',
    'match': {
        'meta.last_feature': ['10.0.1.1', 32],
        'meta.last_threshold': ['10.0.1.1', 32],
        'meta.last_res': ['10.0.1.1', 32]
    },
    'action_name': 'RFIngress.rf_compute_%d_%d',
    'action_params': {
        'feature': 0,
        'threshold': 0,
        'result': 0
    }
}

p4_base_tmpl = '''/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8>  TYPE_TCP = 0x06;
const bit<8>  TYPE_UDP = 0x11;
const bit<9> DOWNSTREAM_PORT = 6;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9> port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> ip6Addr_t;
typedef bit<8> uint8_t;
typedef bit<64> uint64_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> nxt;
    bit<8> hop_limit;
    ip6Addr_t source_address;
    ip6Addr_t destination_address;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flag;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
    tcp_t tcp;
    udp_t udp;
}

struct metadata {
    /* Features */
    uint64_t feature_1;
    uint64_t feature_2;
    uint64_t feature_3;
    uint64_t feature_4;
    uint64_t feature_5;
    uint64_t feature_6;
    uint64_t feature_7;
    uint64_t feature_8;
    uint64_t feature_9;
    uint64_t feature_10;
    uint64_t feature_11;

    uint8_t class_1;
    uint8_t class_2;
    uint8_t class_3;
    uint8_t class_4;
    uint8_t class_5;

    uint8_t last_feature;
    uint64_t last_threshold;
    uint8_t last_res;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser RFParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.feature_1 = 0xffffffffffffffff;
        meta.feature_2 = 0xffffffffffffffff;
        meta.feature_3 = 0xffffffffffffffff;
        meta.feature_4 = 0xffffffffffffffff;
        meta.feature_5 = 0xffffffffffffffff;
        meta.feature_6 = 0xffffffffffffffff;
        meta.feature_7 = 0xffffffffffffffff;
        meta.feature_8 = 0xffffffffffffffff;
        meta.feature_9 = 0xffffffffffffffff;
        meta.feature_10 = 0xffffffffffffffff;
        meta.feature_11 = 0xffffffffffffffff;
        meta.class_1 = 0;
        meta.class_2 = 0;
        meta.class_3 = 0;
        meta.class_4 = 0;
        meta.class_5 = 0;
        meta.last_feature = 0;
        meta.last_threshold = 0;
        meta.last_res = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.feature_2 = (uint64_t) hdr.ethernet.etherType;
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.feature_1 = (uint64_t) hdr.ipv4.totalLen + 14;
        meta.feature_3 = (uint64_t) hdr.ipv4.protocol;
        meta.feature_4 = (uint64_t) hdr.ipv4.flags;
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        meta.feature_1 = (uint64_t) hdr.ipv6.payload_length + 54;
        meta.feature_5 = (uint64_t) hdr.ipv6.nxt;
        if (hdr.ipv6.nxt == 60) {
            meta.feature_6 = (uint64_t) 1;
        }
        transition select(hdr.ipv6.nxt) {
            TYPE_UDP: parse_udp;
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.feature_7 = (uint64_t) hdr.tcp.srcPort;
        meta.feature_8 = (uint64_t) hdr.tcp.dstPort;
        meta.feature_9 = (uint64_t) hdr.tcp.flag;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.feature_10 = (uint64_t) hdr.udp.srcPort;
        meta.feature_11 = (uint64_t) hdr.udp.dstPort;
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control RFVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control RFIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action forward_upstream() {
        uint8_t max;
        port_t port;
        max = 0;
        port = 0;
        if (meta.class_1 > max) {
            max = meta.class_1;
            port = 1;
        }
        if (meta.class_2 > max) {
            max = meta.class_2;
            port = 2;
        }
        if (meta.class_3 > max) {
            max = meta.class_3;
            port = 3;
        }
        if (meta.class_4 > max) {
            max = meta.class_4;
            port = 4;
        }
        if (meta.class_5 > max) {
            max = meta.class_5;
            port = 5;
        }
        standard_metadata.egress_spec = port;
    }
%s
    apply {
        if (standard_metadata.ingress_port == DOWNSTREAM_PORT) {%s
            forward_upstream();
        } else {
            standard_metadata.egress_spec = DOWNSTREAM_PORT;
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control RFEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control RFComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control RFDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
RFParser(),
RFVerifyChecksum(),
RFIngress(),
RFEgress(),
RFComputeChecksum(),
RFDeparser()
) main;
'''
ctrl_flow_tmpl = '''
            rf_tree_%d_%d.apply();
            if (meta.last_feature != 0) {%s}'''
table_def_tmpl = '''
    action rf_compute_%d_%d(uint8_t feature, uint64_t threshold,
                            uint8_t result) {
        uint8_t right;
        meta.last_feature = feature;
        meta.last_threshold = threshold;

        right = 1;
        if ((feature == 1 && meta.feature_1 <= threshold)
            || (feature == 2 && meta.feature_2 <= threshold)
            || (feature == 3 && meta.feature_3 <= threshold)
            || (feature == 4 && meta.feature_4 <= threshold)
            || (feature == 5 && meta.feature_5 <= threshold)
            || (feature == 6 && meta.feature_6 <= threshold)
            || (feature == 7 && meta.feature_7 <= threshold)
            || (feature == 8 && meta.feature_8 <= threshold)
            || (feature == 9 && meta.feature_9 <= threshold)
            || (feature == 10 && meta.feature_10 <= threshold)
            || (feature == 11 && meta.feature_11 <= threshold)) {

            right = 0;
        }

        if (result == 1) {
            meta.class_1 = meta.class_1 + 1;
        } else if (result == 2) {
            meta.class_2 = meta.class_2 + 1;
        } else if (result == 3) {
            meta.class_3 = meta.class_3 + 1;
        } else if (result == 4) {
            meta.class_4 = meta.class_4 + 1;
        } else if (result == 5) {
            meta.class_5 = meta.class_5 + 1;
        }

        meta.last_res = (meta.last_res << 1) + 1 + right;
    }

    table rf_tree_%d_%d {
        key = {
            meta.last_feature: exact;
            meta.last_threshold: exact;
            meta.last_res: exact;
        }
        actions = {
            NoAction;
            rf_compute_%d_%d;
        }
        size = %d;
    }
'''


def parse_args(args):
    parser = ArgumentParser(prog=args[0],
                            description='Model.json to P4 generator')
    parser.add_argument('input_file', help='Input Random Forest model.json')
    parser.add_argument('output_code', help='Output P4 code')
    parser.add_argument('output_cfg', help='Output P4 runtime config')
    return parser.parse_args(args[1:])


def get_depth(node):
    _, _, left_child, right_child = node
    left_depth = 1 if isinstance(left_child, int) else get_depth(left_child)
    right_depth = 1 if isinstance(right_child, int) else get_depth(right_child)
    return max(left_depth, right_depth) + 1


def gen_ctrl_flow(tree_depths):
    p4_str = ''
    for tree_id, depth in enumerate(tree_depths):
        tree_str = '\n\n            /* Tree %d */%s' % (tree_id, '%s')
        for table_id in range(0, depth):
            tree_str = tree_str % (ctrl_flow_tmpl % (tree_id, table_id, '%s'))
        p4_str += tree_str % ''
        p4_str += '\n            meta.last_res = 0;'
    return p4_str


def gen_table_defs(tree_depths):
    p4_str = ''
    for tree_id, depth in enumerate(tree_depths):
        tree_str = '\n    /* Tree %d */' % tree_id
        for table_id in range(0, depth):
            tree_str += table_def_tmpl %(tree_id, table_id, tree_id,
                                         table_id, tree_id, table_id, 2**(table_id + 1))
        p4_str += tree_str
    return p4_str


def gen_node_table_entries(tree_id, node_id, depth, node, lookup):
    feature, threshold, left_child, right_child = node
    feature += 1

    if depth == 0:
        lookup[tree_id][0].append({
            'table': 'RFIngress.rf_tree_%d_0' % tree_id,
            'default_action': True,
            'action_name': 'RFIngress.rf_compute_%d_0' % tree_id,
            'action_params': {
                'feature': feature,
                'threshold': threshold,
                'result': 0
            }
        })

    if isinstance(left_child, int):
        lookup[tree_id][depth + 1].append({
            'table': 'RFIngress.rf_tree_%d_%d' % (tree_id, depth + 1),
            'match': {
                'meta.last_feature': feature,
                'meta.last_threshold': threshold,
                'meta.last_res': node_id * 2 + 1
            },
            'action_name': 'RFIngress.rf_compute_%d_%d' % (tree_id, depth + 1),
            'action_params': {
                'feature': 0,
                'threshold': 0,
                'result': left_child + 1
            }
        })
    else:
        lookup[tree_id][depth + 1].append({
            'table': 'RFIngress.rf_tree_%d_%d' % (tree_id, depth + 1),
            'match': {
                'meta.last_feature': feature,
                'meta.last_threshold': threshold,
                'meta.last_res': node_id * 2 + 1
            },
            'action_name': 'RFIngress.rf_compute_%d_%d' % (tree_id, depth + 1),
            'action_params': {
                'feature': left_child[0] + 1,
                'threshold': left_child[1],
                'result': 0
            }
        })
        gen_node_table_entries(tree_id, node_id * 2 + 1, depth + 1, left_child,
                               lookup)

    if isinstance(right_child, int):
        lookup[tree_id][depth + 1].append({
            'table': 'RFIngress.rf_tree_%d_%d' % (tree_id, depth + 1),
            'match': {
                'meta.last_feature': feature,
                'meta.last_threshold': threshold,
                'meta.last_res': node_id * 2 + 2
            },
            'action_name': 'RFIngress.rf_compute_%d_%d' % (tree_id, depth + 1),
            'action_params': {
                'feature': 0,
                'threshold': 0,
                'result': right_child + 1
            }
        })
    else:
        lookup[tree_id][depth + 1].append({
            'table': 'RFIngress.rf_tree_%d_%d' % (tree_id, depth + 1),
            'match': {
                'meta.last_feature': feature,
                'meta.last_threshold': threshold,
                'meta.last_res': node_id * 2 + 2
            },
            'action_name': 'RFIngress.rf_compute_%d_%d' % (tree_id, depth + 1),
            'action_params': {
                'feature': right_child[0] + 1,
                'threshold': right_child[1],
                'result': 0
            }
        })
        gen_node_table_entries(tree_id, node_id * 2 + 2, depth + 1,
                               right_child, lookup)


def gen_config(model, tree_depths):
    res = []
    lookup = [[[] for _ in range(0,x)] for x in tree_depths]

    for tree_id, tree in enumerate(model):
        gen_node_table_entries(tree_id, 0, 0, tree, lookup)

    for tree in lookup:
        for table in tree:
            res += table
    return res


def main():
    options = parse_args(sys.argv)
    try:
        with open(options.input_file, 'r', encoding='utf-8') as fis:
            model = json.loads(fis.read())['tree']
    except (IOError, ValueError) as err:
        sys.exit("Could not read input model: " + str(err))
    except KeyError:
        sys.exit("Invalid model.json format!")

    tree_depths = list(map(get_depth, model))
    code = p4_base_tmpl % (gen_table_defs(tree_depths),
                           gen_ctrl_flow(tree_depths))
    config = dict(config_base_tmpl)
    config['table_entries'] = gen_config(model, tree_depths)
    try:
        with open(options.output_code, 'w+', encoding='utf-8') as fos:
            fos.write(code)
        with open(options.output_cfg, 'w+', encoding='utf-8') as fos:
            fos.write(json.dumps(config, indent=4))
    except IOError as err:
        sys.exit("Could not write output file(s): " + str(err))


if __name__ == '__main__':
    main()
