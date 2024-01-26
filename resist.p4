/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "includes/headers.p4"

//#define DROP_REPLICATION_EXPERIMENT false


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_RES:  parse_resist;
            default: accept;
        }
    }

    #include "includes/modules/Resist/parser_state"

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

register<bit<32>>(1) roundNumber;
register<bit<32>>(1) simulateFailure;
register<bit<32>>(1) lastRoundNumber;
register<bit<32>>(1) causality_violation;

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action multicast() {
      standard_metadata.mcast_grp = 1;
    }


    action bounce_pkt() {
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        bit<48> tmpEth = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmpEth;

        bit<32> tmpIp = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmpIp;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        //hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action clone_packet_ingress() {
        const bit<32> REPORT_MIRROR_SESSION_ID_2 = 1;
        // Clone from ingress to egress pipeline
        clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID_2);
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

apply {
    /*--- simulate failures by droping everything --- */
    simulateFailure.read(meta.simulateFailure, 0);
    if(meta.simulateFailure == 1){
        drop();
    } else{
        if(hdr.ipv4.isValid()){
            ipv4_lpm.apply();
            if(hdr.resist.isValid()){
                //heartbeats
                if(hdr.resist.type == PKT_PING){
                    hdr.resist.type = PKT_PONG;
                    bounce_pkt();
                }

                //Collection packets (from the controller)
                /*collection packets extract a round number and are forwarded to the coordinator*/
                if(hdr.resist.type == PKT_COLLECT_ROUND){
                    roundNumber.read(meta.current_round, 0);
                    hdr.resist.round = meta.current_round;
                    hdr.resist.type = PKT_EXPORT_ROUND;
                    bounce_pkt();
                }

                //if packet is unordered (i.e, packet came from a replica)
                if(hdr.resist.type == PKT_UNORDERED_REPLAY){ //change type. This is not unordered `replay`
                    bounce_pkt();
                }

                if (hdr.resist.type == PKT_UNORDERED){
                    meta.mark_to_bounce = 10;
                }else{
                    if(hdr.resist.type == PKT_FROM_MASTER_TO_REPLICA ){
                        roundNumber.read(meta.current_round, 0);
                        if(meta.current_round + 1 != hdr.resist.round){
                            causality_violation.read(meta.causality_v_counter, 0);
                            causality_violation.write(0, meta.causality_v_counter+1);
                            hdr.resist.type = PKT_UNORDERED;
                            bounce_pkt();
                        }
                    }
                }

                /*this are the possibilities for packet replay*/
                if(hdr.resist.type == PKT_REPLAY_FROM_SHIM){
                    roundNumber.read(meta.current_round, 0);
                    if(meta.current_round + 1 != hdr.resist.round){   //this is an out of order packet
                        causality_violation.read(meta.causality_v_counter, 0);
                        causality_violation.write(0, meta.causality_v_counter+1);
                        hdr.resist.type = PKT_UNORDERED_REPLAY;
                        bounce_pkt();
                    }else{
                        /*send warning to shim layers that the replay has ended.
                        last round number is configured by the controller */
                        lastRoundNumber.read(meta.last_round_number, 0);
                        if(meta.current_round + 1 == meta.last_round_number && meta.last_round_number > 0){
                            hdr.resist.type = LAST_PACKET_RECEIVED;  //this packet also needs to be processed
                        }
                    }
                }

                /*this message is from the controller*/
                if(hdr.resist.type == PKT_LAST_REPLAY_ROUND){
                   lastRoundNumber.write(0, hdr.resist.round);
                   drop();
                }

                //process the INC (last packet received and pkt replay from shim are the same thing)
                if (hdr.resist.type == PKT_FROM_SHIM_LAYER  || hdr.resist.type == LAST_PACKET_RECEIVED || hdr.resist.type == PKT_FROM_MASTER_TO_REPLICA  || hdr.resist.type == PKT_REPLAY_FROM_SHIM){
                    roundNumber.read(meta.current_round, 0);
                    hdr.resist.round = meta.current_round + 1;
                    roundNumber.write(0, meta.current_round + 1);
                    /*** INC IS HERE**/
                    //ipv4_lpm.apply();
                }

                if(hdr.resist.type == PKT_FROM_SHIM_LAYER){
                    hdr.resist.type = PKT_FROM_SWITCH_TO_APP;
                }
                if(hdr.resist.type == PKT_FROM_MASTER_TO_REPLICA){
                    drop();
                }
                if(hdr.resist.type == PKT_REPLAY_FROM_SHIM){
                    hdr.resist.type = PKT_REPLAY_ACK;
                    bounce_pkt();
                }
                if(meta.mark_to_bounce == 10){
                    hdr.resist.type = PKT_FROM_MASTER_TO_REPLICA;
                    bounce_pkt();
                }
                if(hdr.resist.type == LAST_PACKET_RECEIVED){
                    multicast();
                }
            }
        }
    }
}
}

/*
if (hdr.resist.isValid() && hdr.resist.type != PKT_UNORDERED_REPLAY) {
    ipv4_lpm.apply();
}*/


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action bounce_pkt() {
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        bit<48> tmpEth = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmpEth;

        bit<32> tmpIp = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmpIp;
    }

    action recirculate_packet() {
        // Send again the packet through both pipelines
        recirculate_preserving_field_list(RECIRC_FL_1);
    }

    action clone_packet() {
        const bit<32> REPORT_MIRROR_SESSION_ID = 500;
        // Clone from ingress to egress pipeline
        clone(CloneType.E2E, REPORT_MIRROR_SESSION_ID);
    }

    apply {
        //packet was cloned and will be an ack. Go again to the ingress to set correct ports
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE && hdr.resist.type==PKT_FROM_MASTER_TO_REPLICA ){
            hdr.resist.type = PKT_APP_ACK;
            bounce_pkt();
            recirculate_packet();
        //packet that will be forwarded to the replica
        }else if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {

            #ifdef DROP_REPLICATION_EXPERIMENT
            if(hdr.resist.round == 20){
                drop();
            }
            #endif

            hdr.resist.type = PKT_FROM_MASTER_TO_REPLICA;
            clone_packet();
        }else{
          if(hdr.resist.isValid() && hdr.resist.type==PKT_FROM_SWITCH_TO_APP){
              clone_packet();   //original packet will be forwarded to the destination
          }
       }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.resist);
        packet.emit(hdr.ipv4);
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
