#!/usr/bin/env python2
import argparse
import datetime
import os
import struct
import sys
import threading
import time
from collections import defaultdict

import grpc
import networkx as nx
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
from p4.v1 import p4runtime_pb2
from scapy.layers.l2 import Ether

from utils import helper, bmv2, convert

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
from utils.switch import ShutdownAllSwitchConnections

CPU_PORT = 257
TYPE_PROBE = 5


class Probe_Sender(object):
    def __init__(self, switch):
        super(Probe_Sender, self).__init__()
        self.sw = switch

    def generate_probe_packet(self, port, topo):
        pkt = Ether(src='00:00:00:00:00:00', dst="ff:ff:ff:ff:ff:ff")
        topo = struct.pack("!%ds" % len(topo), topo)

        pkt = pkt / topo

        zeros = struct.pack(">q", 0)
        ingress_port = struct.pack(">H", port)
        type = struct.pack(">H", 5)

        timestamp = time.mktime(datetime.datetime.now().timetuple())  
        timestamp = time.time() * 100 
        timestamp = struct.pack(">q", timestamp)

        switch_id = struct.pack(">H", int(self.sw.name[1:]))
        src_port = struct.pack(">H", int(port))

        header = zeros + ingress_port + type + timestamp + switch_id + src_port
        return (header + str(pkt))

    def run(self, topo):
        for i in range(1, 64):
            packet_out = p4runtime_pb2.PacketOut()
            packet_out.payload = self.generate_probe_packet(i, topo)
            self.sw.PacketOut(packet_out)


class Controller(object):
    def __init__(self, switches):
        # threading.Thread.__init__(self)
        self.switches = switches
        #use multithreads to implement listenning to multiple switches
        self.listen_threads = []


        self.mac_to_port = defaultdict(dict)
        self.net = nx.DiGraph()
        self.timestamp_set = set()
        #record ports which connect to switch
        self.switch2_switch_port = defaultdict(set)
        #record swtich-host connect relations
        self.switch_host = defaultdict(set)

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
        self.p4info_helper = p4info_helper
        flag = True
        print 'enter'
        probe_Sender = Probe_Sender(switch)
        init_topo = "+".join(str(edge) for edge in self.net.edges)

        while True:
            #send initial topology
            if flag:
                probe_Sender.run(init_topo)
                flag = False

            #read information form packetin packet
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
                    #use timestamp to filter duplications
                    if timestamp not in self.timestamp_set:
                        renew_flag = False
                        self.timestamp_set.add(timestamp)

                        topo_receive = struct.unpack("!%ds" % len(payload[24:]), payload[24:])
                        print switch.name, "topo_receive ", topo_receive, "from ", switch_id
                        src_sw_id = "s%d" % switch_id

                        #every time we receive information from a swtich, update the link information
                        self.net.add_edge(switch.name, src_sw_id, src_port=in_port, dst_port=src_port)
                        self.net.add_edge(src_sw_id, switch.name, src_port=src_port, dst_port=in_port)

                        self.switch2_switch_port[src_sw_id].add(src_port)
                        self.switch2_switch_port[switch.name].add(in_port)

                        #update the topo
                        if topo_receive[0].find('(') != -1:
                            topo_receive = topo_receive[0][(topo_receive[0].find('(')):].split('+')
                            for edge in topo_receive:
                                nodes = edge.split(',')
                                in_node = eval(nodes[0][1:])
                                out_node = eval(nodes[1][1:-1])
                                if not self.net.has_edge(in_node, out_node):
                                    self.net.add_edge(in_node, out_node)
                                    self.net.add_edge(out_node, in_node)

                        #if the topo we receive is different with the topo we have now, send update information
                        self_topo = [str(edge) for edge in self.net.edges]
                        # print "self_topo", self_topo
                        # print "topo_receive", topo_receive
                        if self_topo != topo_receive:
                            renew_flag = True

                        if renew_flag:
                            print switch.name, "new_topo", self.net.edges
                            new_topo = "+".join(str(edge) for edge in self.net.edges)
                            probe_Sender.run(new_topo)


                # arp packet
                else:
                    if not self.mac_to_port[switch.name].has_key(pkt_eth_src):
                        self.mac_to_port[switch.name][pkt_eth_src] = in_port
                    # avoid receiving broadcast arp packet that send by the switch itself
                    elif in_port in self.switch2_switch_port[switch.name] and pkt_eth_src in self.switch_host[
                        switch.name]:
                        continue

                    # add host to net
                    if pkt_eth_src not in self.net and in_port not in self.switch2_switch_port[switch.name]:
                        self.net.add_edge(pkt_eth_src, switch.name, src_port=-1, dst_port=in_port)
                        self.net.add_edge(switch.name, pkt_eth_src, src_port=in_port, dst_port=-1)
                        self.switch_host[switch.name].add(pkt_eth_src)

                    '''
                    if we don't know the dst mac address, we just record the src mac address and its inport.
                    '''
                    if pkt_eth_dst not in self.mac_to_port[switch.name]:
                        # broadcast the arp packet
                        for i in range(1, 64):
                            if i != in_port:
                                self.patckout(i, in_port, payload, switch)
                    # if we know the dst mac, we can write the flow table
                    else:
                        # find shortest path
                        if pkt_eth_src in self.net and pkt_eth_dst in self.net and switch.name in self.net:
                            path = nx.shortest_path(self.net, pkt_eth_src, pkt_eth_dst)
                            if switch.name in path:
                                next = path[path.index(switch.name) + 1]
                                print switch.name, next
                                out_port = self.net[switch.name][next]['src_port']
                                self.mac_to_port[switch.name][pkt_eth_dst] = out_port

                        # write rules
                        self.writeIpv4Rules(p4info_helper, switch, pkt_eth_src, pkt_eth_dst,
                                            self.mac_to_port[switch.name][pkt_eth_dst],
                                            self.mac_to_port[switch.name][pkt_eth_src])
                        self.writeIpv4Rules(p4info_helper, switch, pkt_eth_dst, pkt_eth_src,
                                            self.mac_to_port[switch.name][pkt_eth_src],
                                            self.mac_to_port[switch.name][pkt_eth_dst])
                        self.readTableRules(p4info_helper, switch)

                        # packet out
                        zeros = struct.pack(">q", 0)
                        ingress_port = struct.pack(">H", in_port)
                        type = struct.pack(">H", 0)

                        timestamp = time.mktime(datetime.datetime.now().timetuple())
                        timestamp = struct.pack(">q", timestamp)

                        switch_id = struct.pack(">H", int(switch.name[1:]))
                        #we already know the right port to transfer the packet, so we don't broadcast
                        src_port = struct.pack(">H", self.mac_to_port[switch.name][pkt_eth_dst])

                        header = zeros + ingress_port + type + timestamp + switch_id + src_port

                        packet_out = p4runtime_pb2.PacketOut()
                        packet_out.payload = (header + payload[24:])
                        switch.PacketOut(packet_out)

                        # send topo update information
                        topo = "+".join(str(edge) for edge in self.net.edges)
                        probe_Sender.run(topo)

    def patckout(self, i, in_port, payload, switch):
        zeros = struct.pack(">q", 0)
        ingress_port = struct.pack(">H", in_port)
        type = struct.pack(">H", 0)

        timestamp = time.mktime(datetime.datetime.now().timetuple())
        timestamp = struct.pack(">q", timestamp)

        switch_id = struct.pack(">H", int(switch.name[1:]))
        src_port = struct.pack(">H", int(i))
        header = zeros + ingress_port + type + timestamp + switch_id + src_port

        packet_out = p4runtime_pb2.PacketOut()
        packet_out.payload = (header + payload[24:])
        switch.PacketOut(packet_out)

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
                self.readTableRules(p4info_helper, switch)

            # start switch
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
