from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu import utils

from ryu.lib import hub
from pydantic import BaseModel
from typing import Dict, Optional, Any, List
from enum import Enum

from ryu.topology import event
from ryu.topology.api import get_all_host, get_all_link, get_all_switch, get_host, get_switch, get_link
import copy
from ryu.topology.switches import Port, Switch
from ryu.controller.controller import Datapath


class NodeType(Enum):
    OF_SWITCH = 1
    HOST = 2


class Node(BaseModel):
    node_type: NodeType
    mac: Optional[str]
    ipv4: Optional[str]
    datapath: Optional[Any]
    neighbours: Dict[int, 'Node'] = {}  # port to node
    mac_to_port: Dict[str, int]  # mac to port for faster access
    ports: List[Port]

    class Config:
        use_enum_values = True
        arbitrary_types_allowed = True


Node.update_forward_refs()


class MULTIPATH_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MULTIPATH_13, self).__init__(*args, **kwargs)
        self.net_graph = {}  # datapath.id to Node
        self.mac_to_port = {}  # for arp
        self.hosts = {}  # mac to host
        self.mutex = hub.BoundedSemaphore()

        self.monitor_thread = hub.spawn(self.query_switch_statistics)

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s', msg.type, msg.code,
                          utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)
        self.logger.info("switch:%s connected", dpid)

    def add_flow(self, datapath, hard_timeout, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER,
                                     ofproto.OFPP_FLOOD, msg.data)
        datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst)
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 0, 1, match, actions)
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)

    def mac_learning(self, dpid, src_mac, in_port, ipv4=None):
        self.mac_to_port.setdefault(dpid, {})
        if src_mac in self.mac_to_port[dpid]:
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
        else:
            self.mac_to_port[dpid][src_mac] = in_port
        return True

    @ set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6)
            self.add_flow(datapath, 0, 1, match, actions)
            return

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return

            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            mac_to_port_table = self.mac_to_port.get(dpid)
            if mac_to_port_table is None:
                self.logger.info("Dpid is not in mac_to_port")
                return

            out_port = mac_to_port_table.get(eth.dst)
            if out_port is not None:
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst,
                                        eth_type=eth.ethertype)
                self.add_flow(datapath, 0, 1, match, actions)
                self.send_packet_out(datapath, msg.buffer_id, in_port,
                                     out_port, msg.data)
            else:
                if self.mac_learning(dpid, eth.src, in_port) is False:
                    self.logger.debug("IPV4 packet enter in different ports")
                    return
                else:
                    self.flood(msg)

    def query_switch_statistics(self):
        return
        # while True:
        #     hub.sleep(1)
        #     for node in self.net_graph.values():
        #         dp = node.datapath
        #         ofp = dp.ofproto
        #         ofp_parser = dp.ofproto_parser
        #         req = ofp_parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY)
        #         print('Sent ', req)
        #         dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        ports = []
        for stat in ev.msg.body:
            ports.append('port_no=%d '
                         'rx_packets=%d tx_packets=%d '
                         'rx_bytes=%d tx_bytes=%d '
                         'rx_dropped=%d tx_dropped=%d '
                         'rx_errors=%d tx_errors=%d '
                         'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                         'collisions=%d duration_sec=%d duration_nsec=%d' %
                         (stat.port_no,
                          stat.rx_packets, stat.tx_packets,
                          stat.rx_bytes, stat.tx_bytes,
                          stat.rx_dropped, stat.tx_dropped,
                          stat.rx_errors, stat.tx_errors,
                          stat.rx_frame_err, stat.rx_over_err,
                          stat.rx_crc_err, stat.collisions,
                          stat.duration_sec, stat.duration_nsec))
        print('PortStats: ', ports)

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        dp = ev.switch.dp
        self.add_new_switches()

        # add links to net_graph
        topo_raw_links = copy.copy(get_link(self))
        for l in topo_raw_links:
            if l.src.dpid == dp.id or l.dst.dpid == dp.id:
                self.add_link(l.src, l.dst)

        print('Switch {} entered'.format(dp.id))
        print('\t\t', self.net_graph, '\n')

    @set_ev_cls(event.EventHostAdd)
    def handler_new_host(self, ev):
        hosts = copy.copy(get_host(self))
        for host in hosts:
            self.hosts[host.mac] = host

    def add_link(self, src: Port, dst: Port):
        try:
            self.mutex.acquire()
            self.net_graph[src.dpid].neighbours[src.port_no] = self.net_graph[dst.dpid]
        finally:
            self.mutex.release()

    def add_new_switches(self):
        switches = copy.copy(get_switch(self))
        try:
            self.mutex.acquire()
            for sw in switches:
                datapath = self.net_graph.get(sw)
                if datapath is not None:
                    continue

                # assume ports start from 1 and are ordered Port
                node = Node(node_type=NodeType.OF_SWITCH, datapath=sw.dp,
                            neighbours={}, mac_to_port={}, ports=sw.ports)
                # validate assumption
                for i in range(len(node.ports)):
                    if node.ports[i].port_no != i+1:
                        raise "port order assumption failed"

                self.net_graph[sw.dp.id] = node
        finally:
            self.mutex.release()
