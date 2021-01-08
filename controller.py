#!/usr/bin/env python2
import argparse
import os
import sys
import threading
from collections import defaultdict
from random import random, randint
from time import sleep

from scapy.contrib.lldp import LLDPDU
from scapy.layers.l2 import Ether
from threading import Thread
from scapy.contrib import lldp
import uuid

import grpc
import networkx
import struct
import thread
import networkx as nx

import time, datetime
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
from p4.v1 import p4runtime_pb2

from utils import helper, bmv2, convert

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
from utils.switch import ShutdownAllSwitchConnections

CPU_PORT = 257
TYPE_PROBE = 5


class LLDP_Sender(object):
    def __init__(self, switch):
        super(LLDP_Sender, self).__init__()
        self.sw = switch

    def generate_lldp_packet(self, port, topo):
        pkt = Ether(src='00:00:00:00:00:00', dst="ff:ff:ff:ff:ff:ff")
        topo = struct.pack("!%ds" % len(topo), topo)

        pkt = pkt / topo

        zeros = struct.pack(">q", 0)
        ingress_port = struct.pack(">H", port)
        type = struct.pack(">H", 5)

        timestamp = time.mktime(datetime.datetime.now().timetuple()) # + randint(100000000, 200000000)
        timestamp = time.time() * 100 # + randint(100000000, 200000000)
        # timestamp = time.time_ns()
        timestamp = struct.pack(">q", timestamp)

        switch_id = struct.pack(">H", int(self.sw.name[1:]))
        src_port = struct.pack(">H", int(port))

        header = zeros + ingress_port + type + timestamp + switch_id + src_port
        return (header + str(pkt))

    def run(self, topo):
        for i in range(1, 64):
            packet_out = p4runtime_pb2.PacketOut()
            packet_out.payload = self.generate_lldp_packet(i, topo)
            # print self.sw.name, "sending lldp"
            self.sw.PacketOut(packet_out)


class Controller(object):
    def __init__(self, switches):
        # threading.Thread.__init__(self)
        self.switches = switches
        self.listen_threads = []
        self.mac_to_port = defaultdict(dict)
        self.net = nx.DiGraph()
        self.timestamp_set = set()
        self.switch2_switch_port = defaultdict(set)
        self.switch_host = defaultdict(set)
    #
    # def writeIpv4Rules(self, p4info_helper, sw_id, src_ip_addr, dst_ip_addr, port):
    #     for response in sw_id.ReadTableEntries():
    #         for entity in response.entities:
    #             entry = entity.table_entry
    #             m1 = p4info_helper.get_match_field_value(entry.match[0])
    #             m2 = p4info_helper.get_match_field_value(entry.match[1])
    #
    #             n1 = convert.encode(src_ip_addr, 48)
    #             n2 = convert.encode(dst_ip_addr, 48)
    #             if m1 == n1 and m2 == n2:
    #                 sw_id.DeletePreEntry(entry)
    #     table_entry = p4info_helper.buildTableEntry(
    #         table_name="MyIngress.ipv4_exact",
    #         match_fields={
    #             "hdr.ethernet.srcAddr": src_ip_addr,
    #             "hdr.ethernet.dstAddr": dst_ip_addr
    #         },
    #         action_name="MyIngress.ipv4_forward",
    #         action_params={
    #             "port": port
    #         })
    #     sw_id.WriteTableEntry(table_entry)
    #     print "Installed ingress forwarding rule on %s" % sw_id.name

    def writeIpv4Rules(self, p4info_helper, sw_id, src_ip_addr, dst_ip_addr, port, inport):
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
                "hdr.ethernet.dstAddr": dst_ip_addr,
                "standard_metadata.ingress_port": inport
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": port
            })
        sw_id.WriteTableEntry(table_entry)
        print "Installed ingress forwarding rule on %s" % sw_id.name

    def writeFloodingRules(self, p4info_helper, sw_id, src_ip_addr, dst_ip_addr):
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

    def writeBroadcastRules(self, p4info_helper, sw_id):
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

    def writeIpv4ForceForwardRules(self, p4info_helper, sw_id):
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_exact",
            match_fields={
                "hdr.ethernet.srcAddr": "00:00:00:00:00:00",
                "hdr.ethernet.dstAddr": "ff:ff:ff:ff:ff:ff"
            },
            action_name="MyIngress.ipv4_force_forward",
            action_params={
            })
        sw_id.WriteTableEntry(table_entry)
        print "Installed ipv4_force_forward rule on %s" % sw_id.name

    def readTableRules(self, p4info_helper, sw):
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
        print '\n----Read topo information for %s -------' % sw.name
        print self.net.edges

    def printGrpcError(self, e):
        print "gRPC Error:", e.details(),
        status_code = e.code()
        print "(%s)" % status_code.name,
        traceback = sys.exc_info()[2]
        print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

    def listen_loop(self, switch, p4info_helper):

        # self.switch = switch
        self.p4info_helper = p4info_helper

        # try:
        flag = True
        print 'enter'
        lldp_Sender = LLDP_Sender(switch)
        init_topo = "+".join(str(edge) for edge in self.net.edges)
        # time.sleep(1)
        # lldp_Sender.run(init_topo)

        while True:
            if flag:
                lldp_Sender.run(init_topo)
                flag = False

            packetin = switch.PacketIn()
            payload = packetin.packet.payload
            pkt = Ether(_pkt=payload[24:])
            zeros = struct.unpack(">q", payload[:8])[0]
            in_port = struct.unpack(">H", payload[8:10])[0]
            type = struct.unpack(">H", payload[10:12])[0]
            timestamp = struct.unpack(">q", payload[12:20])[0]
            switch_id = struct.unpack(">H", payload[20:22])[0]
            src_port = struct.unpack(">H", payload[22:24])[0]

            if zeros == 0:
                pkt_eth_src = pkt.getlayer(Ether).src
                pkt_eth_dst = pkt.getlayer(Ether).dst
                ether_type = pkt.getlayer(Ether).type

                # self send lldp
                if type == TYPE_PROBE:
                    # topo_receive = struct.unpack("!%ds" % len(payload[24:]), payload[24:])
                    # print switch.name, "topo_receive ", topo_receive
                    # print "timestamp", timestamp
                    # try:
                    if timestamp not in self.timestamp_set:
                        renew_flag = False

                        self.timestamp_set.add(timestamp)
                        topo_receive = struct.unpack("!%ds" % len(payload[24:]), payload[24:])
                        print switch.name, "topo_receive ", topo_receive, "from ", switch_id
                        src_sw_id = "s%d" % switch_id
                        # if not self.net.has_edge(switch.name, src_sw_id):
                            # self.net.add_edge(switch.name, src_sw_id, src_port=src_port, dst_port=in_port)
                            # self.net.add_edge(src_sw_id, switch.name, src_port=in_port, dst_port=src_port)
                            #
                            # self.switch2_switch_port[src_sw_id].append(src_port)
                            # self.switch2_switch_port[switch.name].append(in_port)

                        self.net.add_edge(switch.name, src_sw_id, src_port=in_port, dst_port=src_port)
                        self.net.add_edge(src_sw_id, switch.name, src_port=src_port, dst_port=in_port)

                        self.switch2_switch_port[src_sw_id].add(src_port)
                        self.switch2_switch_port[switch.name].add(in_port)

                        # renew_flag = True

                        if topo_receive[0].find('(') != -1:
                            topo_receive = topo_receive[0][(topo_receive[0].find('(')):].split('+')
                            for edge in topo_receive:
                                nodes = edge.split(',')
                                in_node = eval(nodes[0][1:])
                                out_node = eval(nodes[1][1:-1])
                                if not self.net.has_edge(in_node, out_node):
                                    self.net.add_edge(in_node, out_node)
                                    self.net.add_edge(out_node, in_node)

                        self_topo = [str(edge) for edge in self.net.edges]
                        print "self_topo", self_topo
                        print "topo_receive", topo_receive
                        if self_topo != topo_receive:
                            renew_flag = True

                        if renew_flag:
                            print switch.name, "new_topo", self.net.edges
                            new_topo = "+".join(str(edge) for edge in self.net.edges)
                            lldp_Sender.run(new_topo)


                #ping packet
                else:
                    if not self.mac_to_port[switch.name].has_key(pkt_eth_src):
                        self.mac_to_port[switch.name][pkt_eth_src] = in_port
                    elif in_port in self.switch2_switch_port[switch.name] and pkt_eth_src in self.switch_host[switch.name]:
                        continue

                    #add host to net
                    if pkt_eth_src not in self.net and in_port not in self.switch2_switch_port[switch.name]:
                        self.net.add_edge(pkt_eth_src, switch.name, src_port=-1, dst_port=in_port)
                        self.net.add_edge(switch.name, pkt_eth_src, src_port=in_port, dst_port=-1)

                        self.switch_host[switch.name].add(pkt_eth_src)

                    # print switch.name, pkt_eth_src, "in_port", in_port
                    if pkt_eth_dst not in self.mac_to_port[switch.name]:
                        # self.writeFloodingRules(p4info_helper, switch, pkt_eth_src, pkt_eth_dst)

                        # packet_out = p4runtime_pb2.PacketOut()
                        # packet_out.payload = payload

                        for i in range(1, 64):
                            if i != in_port:
                                zeros = struct.pack(">q", 0)
                                ingress_port = struct.pack(">H", in_port)
                                type = struct.pack(">H", 0)

                                timestamp = time.mktime(datetime.datetime.now().timetuple())
                                timestamp = struct.pack(">q", timestamp)

                                switch_id = struct.pack(">H", int(switch.name[1:]))
                                src_port = struct.pack(">H", int(i))

                                header = zeros + ingress_port + type + timestamp + switch_id + src_port
                                #
                                packet_out = p4runtime_pb2.PacketOut()
                                packet_out.payload = (header + payload[24:])
                                switch.PacketOut(packet_out)

                    else:
                        if pkt_eth_src in self.net and pkt_eth_dst in self.net and switch.name in self.net:
                            path = nx.shortest_path(self.net, pkt_eth_src, pkt_eth_dst)
                            if switch.name in path:
                                next = path[path.index(switch.name) + 1]
                                print switch.name, next
                                out_port = self.net[switch.name][next]['src_port']
                                self.mac_to_port[switch.name][pkt_eth_dst] = out_port



                        self.writeIpv4Rules(p4info_helper, switch, pkt_eth_src, pkt_eth_dst,
                                            self.mac_to_port[switch.name][pkt_eth_dst], self.mac_to_port[switch.name][pkt_eth_src])
                        self.writeIpv4Rules(p4info_helper, switch, pkt_eth_dst, pkt_eth_src,
                                            self.mac_to_port[switch.name][pkt_eth_src], self.mac_to_port[switch.name][pkt_eth_dst])
                        self.readTableRules(p4info_helper, switch)

                        #add port
                        zeros = struct.pack(">q", 0)
                        ingress_port = struct.pack(">H", in_port)
                        type = struct.pack(">H", 0)

                        timestamp = time.mktime(datetime.datetime.now().timetuple())
                        timestamp = struct.pack(">q", timestamp)

                        switch_id = struct.pack(">H", int(switch.name[1:]))
                        src_port = struct.pack(">H", self.mac_to_port[switch.name][pkt_eth_dst])

                        header = zeros + ingress_port + type + timestamp + switch_id + src_port

                        packet_out = p4runtime_pb2.PacketOut()
                        packet_out.payload = (header + payload[24:])
                        switch.PacketOut(packet_out)

                        topo = "+".join(str(edge) for edge in self.net.edges)
                        print "lldp send"
                        lldp_Sender.run(topo)
            # deal with arp reply
            # flooding into switch
            else:
                # if timestamp not in self.timestamp_set:
                #     self.timestamp_set.add(timestamp)
                pass
        # except Exception as e:
        #     print e

    def start(self, p4info_file_path, bmv2_file_path):
        p4info_helper = helper.P4InfoHelper(p4info_file_path)

        try:
            # Create a switch connection object for s1 and s2;
            # this is backed by a P4Runtime gRPC connection.
            # Also, dump all P4Runtime messages sent to switch to given txt files.
            for switch in self.switches:
                switch.MasterArbitrationUpdate()
                switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                   bmv2_json_file_path=bmv2_file_path)

                print "Installed P4 Program using SetForwardingPipelineConfig on %s" % switch.name
                mc_group_entry = p4info_helper.buildMulticastGroupEntry(1, replicas=[
                    {'egress_port': 1, 'instance': 1},
                    {'egress_port': 2, 'instance': 2},
                    {'egress_port': 3, 'instance': 3},
                    {'egress_port': 4, 'instance': 4},
                    {'egress_port': 5, 'instance': 5},
                    # {'egress_port': 64, 'instance': 64}

                ])
                switch.WritePREEntry(mc_group_entry)
                print "Installed mgrp on %s." % switch.name
                # self.writeBroadcastRules(p4info_helper, switch)
                # self.writeIpv4ForceForwardRules(p4info_helper, switch)
                self.readTableRules(p4info_helper, switch)

            for switch in self.switches:
                listen_thread = threading.Thread(target=self.listen_loop, args=(switch, p4info_helper))
                listen_thread.setDaemon(True)
                self.listen_threads.append(listen_thread)

            for listen_thread in self.listen_threads:
                listen_thread.start()

            for listen_thread in self.listen_threads:
                listen_thread.join()

        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            self.printGrpcError(e)

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

    s1 = bmv2.Bmv2SwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=1
    )

    s2 = bmv2.Bmv2SwitchConnection(
        name='s2',
        address='127.0.0.1:50052',
        device_id=2
    )

    s3 = bmv2.Bmv2SwitchConnection(
        name='s3',
        address='127.0.0.1:50053',
        device_id=3
    )
    #
    s4 = bmv2.Bmv2SwitchConnection(
        name='s4',
        address='127.0.0.1:50054',
        device_id=4
    )
    #
    # s5 = bmv2.Bmv2SwitchConnection(
    #     name='s5',
    #     address='127.0.0.1:50055',
    #     device_id=5
    # )
    #
    # s6 = bmv2.Bmv2SwitchConnection(
    #     name='s6',
    #     address='127.0.0.1:50056',
    #     device_id=6
    # )

    controller1 = Controller([s1, s2])
    controller2 = Controller([s3])
    controller3 = Controller([s4])

    controller_thread1 = threading.Thread(target=controller1.start, args=(args.p4info, args.bmv2_json))
    # controller_thread1.setDaemon(True)
    controller_thread1.start()

    controller_thread2 = threading.Thread(target=controller2.start, args=(args.p4info, args.bmv2_json))
    # controller_thread2.setDaemon(True)
    controller_thread2.start()

    controller_thread3 = threading.Thread(target=controller3.start, args=(args.p4info, args.bmv2_json))
    # controller_thread2.setDaemon(True)
    controller_thread3.start()

    controller_thread1.join()
    controller_thread2.join()
    # controller_thread3.join()
