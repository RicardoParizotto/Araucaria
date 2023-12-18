const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_RES = 0x600;

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2

#define PKT_FROM_SHIM_LAYER 50
#define PKT_FROM_MASTER_TO_REPLICA 1
#define PKT_PING 2
#define PKT_PONG 3
#define PKT_FROM_SWITCH_TO_APP 7
#define PKT_REPLAY_FROM_SHIM 8
#define PKT_UNORDERED_REPLAY 9
#define PKT_COLLECT_ROUND 10
#define PKT_EXPORT_ROUND 11
#define PKT_LAST_REPLAY_ROUND 12
#define LAST_PACKET_RECEIVED 13
#define PKT_REPLAY_ACK 20
#define PKT_UNORDERED 21

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

#include "modules/Resist/header"

struct metadata {
    bit<32> current_round;
    bit<32> simulateFailure;
    bit<32> causality_v_counter;
    bit<32> last_round_number;
    bit<32> mark_to_bounce;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    #include "modules/Resist/header_instance"
}
