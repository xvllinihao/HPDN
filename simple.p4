/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#define CPU_PORT 64

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<16> TYPE_LLDP_IN = 5;
const bit<16> TYPE_LLDP_OUT = 4;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<48> ip4Addr_t;


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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// packet in
//@controller_header("packet_in")
header packet_in_header_t {
    bit<64>  zeros;
    bit<16>  ingress_port;
    bit<16>  type;
    bit<64>  timestamp;
    bit<16>  switch_id;
    bit<16>  src_port;
}

// packet out
//@controller_header("packet_out")
//header packet_out_header_t {
    //bit<16> egress_port;
    //bit<16> TYPE;
//}

struct metadata {
    //@metadate
    //bit<16>  ingress_port;
    //@metadata @name("TYPE")
    //bit<16>  TYPE;

//    bit<32> counter;
//    bit<8> flow_id;
//    bit<16> count;
//    bit<8> index;
//    bit<1> enabled;
//    bit<32> ingress_port;
}

struct headers {
    packet_in_header_t packet_in_header;
    //packet_out_header_t packet_out_header;
    ethernet_t   ethernet;
    ipv4_t       ipv4;

    //tcp_t        tcp;
}



/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(packet.lookahead<packet_in_header_t>().zeros){
            (bit<64>)0 : parse_packet_in_header;
            //CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
        //packet.extract(hdr.packet_out_header);
        //transition parse_ethernet;
    }
    state parse_packet_in_header {
        packet.extract(hdr.packet_in_header);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }
    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in_header.setValid();
        hdr.packet_in_header.zeros = (bit<64>)0;
        hdr.packet_in_header.ingress_port = (bit<16>)standard_metadata.ingress _port;
        //meta.ingress_port = (bit<16>)standard_metadata.ingress_port;
        //meta.ingress_port = (bit<32>)standard_metadata.ingress_port;
        //hdr.ipv4.setValid();
        //hdr.ipv4.ingress_port = (bit<16>)standard_metadata.ingress_port;
    }
    action ipv4_forward(egressSpec_t port) {
        //if (hdr.packet_out_header.TYPE == TYPE_LLDP) {
            //hdr.packet_in_header.TYPE = TYPE_LLDP;
            //hdr.packet_in_header.ingress_port = hdr.packet_out_header.egress_port;
        //}
        standard_metadata.egress_spec = port;
        hdr.packet_in_header.setValid();
        hdr.packet_in_header.zeros = (bit<64>)0;
        hdr.packet_in_header.ingress_port = (bit<16>)standard_metadata.ingress_port;
    }
    action ipv4_force_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        //standard_metadata.egress_port = (bit<9>)hdr.packet_in_header.src_port;
    }
    action flooding() {
        standard_metadata.mcast_grp = 1;
    }

    table ipv4_exact {
        key = {
            hdr.ethernet.srcAddr: exact;
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            flooding;
            send_to_cpu;
            drop;
            NoAction;
            ipv4_force_forward;
        }
        size = 1024;
        //default_action = drop();
        default_action = send_to_cpu();
    }

    
    apply {
        //if (hdr.ipv4.isValid()) {
        //if (hdr.packet_in_header.isValid()){
            //ipv4_forward();
        //}
        if (hdr.packet_in_header.isValid()) {
            send_to_cpu();
        }
        else{
            ipv4_exact.apply();
        }
       // }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        //if (standard_metadata.egress_spec == CPU_PORT && hdr.packet_in_header.isValid()) {
        //    hdr.packet_in_header.type = 5;
        //}
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	//update_checksum(
	    //hdr.ipv4.isValid(),
            //{ hdr.ipv4.version,
	    //  hdr.ipv4.ihl,
            //  hdr.ipv4.diffserv,
            //  hdr.ipv4.totalLen,
            //  hdr.ipv4.identification,
            //  hdr.ipv4.flags,
            //  hdr.ipv4.fragOffset,
            //  hdr.ipv4.ttl,
            //  hdr.ipv4.protocol,
            //  hdr.ipv4.srcAddr,
            //  hdr.ipv4.dstAddr },
            //hdr.ipv4.hdrChecksum,
            //HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in_header);
        //packet.emit(hdr.packet_out_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        //packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
