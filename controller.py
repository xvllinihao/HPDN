#!/usr/bin/env python2
import argparse
import os
import sys
from collections import defaultdict
from time import sleep

from scapy.layers.l2 import Ether
from threading import Thread
from scapy.contrib import lldp

import grpc
import networkx
import struct
import thread
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
from p4.v1 import p4runtime_pb2

from utils import helper, bmv2, convert

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
from utils.switch import ShutdownAllSwitchConnections


class LLDP_Thread(Thread):
    def __init__(self, switch):
        super(LLDP_Thread, self).__init__()
        self.sw = switch

    def generate_lldp_packet(self, port):
        pkt = Ether(src='00:00:00:00:00:00', dst="ff:ff:ff:ff:ff:ff")
        lldp_chassis_id = lldp.LLDPDUChassisID(id=str.encode(self.sw.name))
        lldp_port_id = lldp.LLDPDUPortID(id=struct.pack(">H", port))
        lldp_time_to_live = lldp.LLDPDUTimeToLive(ttl=1)
        lldp_end_of_lldp = lldp.LLDPDUEndOfLLDPDU()

        pkt = pkt / lldp_chassis_id / lldp_port_id / lldp_time_to_live / lldp_end_of_lldp

        zeros = struct.pack(">q", 0)
        ingress_port = struct.pack(">H", port)
        type = struct.pack(">H", 5)
        header = zeros + ingress_port + type

        print "sending LLDP packet on port" + str(port)
        return (header + str(pkt))

    def run(self):
        for i in range(1, 6):
            packet_out = p4runtime_pb2.PacketOut()
            packet_out.payload = self.generate_lldp_packet(i)
            # del packet_out.metadata[:]
            # p4runtime_metadata1 = p4runtime_pb2.PacketMetadata()
            # p4runtime_metadata1.metadata_id = 1
            # p4runtime_metadata1.value = struct.pack(">H", i)
            # packet_out.metadata.append(p4runtime_metadata1)
            # p4runtime_metadata2 = p4runtime_pb2.PacketMetadata()
            # p4runtime_metadata2.metadata_id = 2
            # p4runtime_metadata2.value = struct.pack(">H", 5)
            # packet_out.metadata.append(p4runtime_metadata2)
            self.sw.PacketOut(packet_out)
            print 'receive'


def writeIpv4Rules(p4info_helper, sw_id, src_ip_addr, dst_ip_addr, port):
    for response in sw_id.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            m1 = p4info_helper.get_match_field_value(entry.match[0])
            m2 = p4info_helper.get_match_field_value(entry.match[1])

            n1 = convert.encode(src_ip_addr, 48)
            n2 = convert.encode(dst_ip_addr, 48)
            if m1 == n1 and m2 == n2:
                sw_id.DeletePreEntry(entry)
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_exact",
        match_fields={
            "hdr.ethernet.srcAddr": src_ip_addr,
            "hdr.ethernet.dstAddr": dst_ip_addr
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "port": port
        })
    sw_id.WriteTableEntry(table_entry)
    print "Installed ingress forwarding rule on %s" % sw_id.name


def writeFloodingRules(p4info_helper, sw_id, src_ip_addr, dst_ip_addr):
    for response in sw_id.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            m1 = p4info_helper.get_match_field_value(entry.match[0])
            m2 = p4info_helper.get_match_field_value(entry.match[1])

            n1 = convert.encode(src_ip_addr, 48)
            n2 = convert.encode(dst_ip_addr, 48)
            if m1 == n1 and m2 == n2:
                sw_id.DeletePreEntry(entry)
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_exact",
        match_fields={
            "hdr.ethernet.srcAddr": src_ip_addr,
            "hdr.ethernet.dstAddr": dst_ip_addr
        },
        action_name="MyIngress.flooding",
        action_params={
        })
    sw_id.WriteTableEntry(table_entry)
    print "Installed ingress flooding rule on %s" % sw_id.name


def writeBroadcastRules(p4info_helper, sw_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_exact",
        match_fields={
            "hdr.ethernet.srcAddr": "00:00:00:00:00:00",
            "hdr.ethernet.dstAddr": "ff:ff:ff:ff:ff:ff"
        },
        action_name="MyIngress.flooding",
        action_params={
        })
    sw_id.WriteTableEntry(table_entry)
    print "Installed broadcast rule on %s" % sw_id.name


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print


def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    mac_to_port = defaultdict(dict)
    p4info_helper = helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = bmv2.Bmv2SwitchConnection(
            name='s0',
            address='127.0.0.1:50051',
            device_id=1)

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        # Write the rules that tunnel traffic from h1-h2 to s1
        # writeIpv4Rules(p4info_helper, sw_id=s1, dst_ip_addr="10.10.10.1", port = 1)
        # writeIpv4Rules(p4info_helper, sw_id=s1, dst_ip_addr="10.10.10.2", port = 2)
        # writeIpv4Rules(p4info_helper, sw_id=s1, dst_ip_addr="10.10.3.3", port = 3)
        # readTableRules(p4info_helper, s1)
        mc_group_entry = p4info_helper.buildMulticastGroupEntry(1, replicas=[
            {'egress_port': 1, 'instance': 1},
            {'egress_port': 2, 'instance': 2},
            {'egress_port': 3, 'instance': 3},
            {'egress_port': 4, 'instance': 4},
            {'egress_port': 5, 'instance': 5},
            {'egress_port': 64, 'instance': 64}

        ])
        s1.WritePREEntry(mc_group_entry)
        print "Installed mgrp on s1."
        writeBroadcastRules(p4info_helper, s1)
        readTableRules(p4info_helper, s1)

        lldp_thread = LLDP_Thread(s1)
        # lldp_thread.run()
        # lldp_thread.start()
        # counter = 0

        while True:
            packetin = s1.PacketIn()
            # counter += 1
            payload = packetin.packet.payload
            pkt = Ether(_pkt=payload[12:])
            # metadata = packetin.packet.metadata[0]
            # metadata_id = metadata.metadata_id
            # port = metadata.value
            # pkt_type = packetin.packet.metadata[1].value
            zeros = struct.unpack(">q", payload[:8])[0]
            port = struct.unpack(">H", payload[8:10])[0]
            type = struct.unpack(">H", payload[10:12])[0]

            if zeros == 0:
                pkt_eth_src = pkt.getlayer(Ether).src
                pkt_eth_dst = pkt.getlayer(Ether).dst
                ether_type = pkt.getlayer(Ether).type

                # self send lldp
                if type == 5:
                    pass
                elif type == 4:
                    pass
                else:
                    lldp_thread.run()
                    # if pkt_eth_src in mac_to_port[s1.name]:
                    #     writeIpv4Rules(p4info_helper,s1,pkt_eth_src,mac_to_port[s1.name][pkt_eth_src])

                    # if ether_type == 2048 or ether_type == 2054:
                    # writeIpv4Rules(p4info_helper, s1, pkt_eth_src, port)

                    mac_to_port[s1.name][pkt_eth_src] = port
                    if pkt_eth_dst not in mac_to_port[s1.name]:
                        writeFloodingRules(p4info_helper, s1, pkt_eth_src, pkt_eth_dst)
                    else:
                        writeIpv4Rules(p4info_helper, s1, pkt_eth_src, pkt_eth_dst, mac_to_port[s1.name][pkt_eth_dst])
                        writeIpv4Rules(p4info_helper, s1, pkt_eth_dst, pkt_eth_src, mac_to_port[s1.name][pkt_eth_src])
                    readTableRules(p4info_helper, s1)

                    packet_out = p4runtime_pb2.PacketOut()
                    packet_out.payload = payload[12:]
                    # def packet_Out(s1,packetout):
                    #     s1.PacketOut(packetout)
                    # thread.start_new_thread(packet_Out,(s1,packet_out))
                    # packet_out.metadata = metadata
                    s1.PacketOut(packet_out)
                    # if counter % 10 == 0:
            else:
                pass

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./firmeware.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./simple.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found!" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found!" % args.bmv2_json
        parser.exit(2)
    main(args.p4info, args.bmv2_json)
