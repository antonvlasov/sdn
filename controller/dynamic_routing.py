from tkinter.constants import S
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet, packet_base
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu import utils

from ryu.lib import hub
from typing import Callable, Dict, Optional, Any, List, Set, Tuple
from enum import Enum

from ryu.topology import event
from ryu.topology.api import get_all_host, get_all_link, get_all_switch, get_host, get_switch, get_link
import copy
from ryu.topology.switches import Port, Switch, Host, Link
from ryu.controller.controller import Datapath

import time
from dataclasses import dataclass, field

import random
from random import randint

import struct

UINT64_MAX = 18446744073709551616

random.seed()


class NodeType(Enum):
    OF_SWITCH = 1
    HOST = 2


@dataclass
class SimplePort:
    dpid: int
    port_no: int
    mac: str
    max_load: int
    load: int


@dataclass
class SimpleHost:
    mac: str
    ipv4: str
    port: SimplePort


@dataclass
class Node:
    node_type: NodeType
    datapath: Optional[Datapath]
    neighbours: Dict[int, 'Node'] = field(default_factory=dict)  # port to node
    ports: Dict[int, SimplePort] = field(default_factory=dict)


class ArpDispatcher:
    # arp request destination to (time of last request; set of sources for such request)
    requests: Dict[str, Tuple[time.time, Set[str]]]
    known_ips: Dict[str, str]
    delay: float

    def __init__(self, delay) -> None:
        self.delay = delay
        self.requests = {}
        self.known_ips = {}

        self._mu = hub.BoundedSemaphore()

    def handle_arp_request(self, src_mac: str, dst_ip: str) -> Tuple[str, bool]:
        try:
            self._mu.acquire()
            if dst_ip in self.known_ips:
                return self.known_ips[dst_ip], None

            if self.requests.get(dst_ip) is None:
                self.requests[dst_ip] = (
                    time.time(), set([src_mac]))
                return None, True

            last_request = self.requests[dst_ip][0]
            self.requests[dst_ip][1].add(src_mac)
            self.requests[dst_ip] = (
                time.time(),  self.requests[dst_ip][1])

            return None, self.requests[dst_ip][0]-last_request > self.delay
        finally:
            self._mu.release()

    def handle_arp_reply(self, ip: str, mac: str) -> List[str]:
        try:
            self._mu.acquire()
            if ip in self.known_ips:
                print(f"duplicate arp reply for one ip {ip}")
                if self.known_ips[ip] != mac:
                    print(
                        f"different mac for same ip in arp reply: know {self.known_ips[ip]}, adding {mac}")
            if ip not in self.requests:
                print(f"no one waiting for arp reply for ip {ip}")
                return

            self.known_ips[ip] = mac
            return self.requests[ip][1]
        finally:
            self._mu.release()


LATENCY_PROBE = 0x07c3


class LatencyProbePacket(packet_base.PacketBase):
    _PACK_STR = '!Q'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TYPE = {
        'ascii': [
            'timestamp'
        ]
    }

    timestamp: int

    def __init__(self, timestamp: int):
        if not 0 < timestamp <= UINT64_MAX:
            raise Exception("timestamp must take 32 bits")
        super().__init__()
        self.timestamp = timestamp

    @ classmethod
    def parser(cls, buf):
        timestamp = struct.unpack_from(cls._PACK_STR, buf)[0]
        return cls(timestamp), None, buf[cls._MIN_LEN:]

    def serialize(self, payload, prev):
        return struct.pack(self._PACK_STR, self.timestamp)


packet_base.PacketBase.register_packet_type(LatencyProbePacket, LATENCY_PROBE)


class NetGraph:
    _node_graph: Dict[int, Node]
    _hosts: Dict[str, SimpleHost]
    _broadcast_targets: Set[Tuple[Datapath, int]]  # datapath and port_no

    def __init__(self, logger) -> None:
        self.logger = logger

        self._node_graph = {}  # datapath.id to Node
        self._hosts = {}  # mac to host
        self.mutex = hub.BoundedSemaphore()
        self._broadcast_targets = set()

    def _update_broadcast_targets(self):
        targets = set()
        for node in self._node_graph.values():
            non_switch_ports = node.ports.keys()-node.neighbours.keys()
            for port in non_switch_ports:
                targets.add((node.datapath, port))
        self._broadcast_targets = targets

    def update_switches(self, switches: List[Switch], links: List[Link]):
        self._update_nodes(switches)
        self._update_links(links)
        self._update_broadcast_targets()

        print(" \t" + "Saved Links:")
        for dpid, s in self._node_graph.items():
            for port, l in s.neighbours.items():
                print(" \t\t dpid: {}, port: {} dpid: {}".format(
                    dpid, port, l.datapath.id))
            print()

    def _update_links(self, links: List[Link]):
        try:
            self.mutex.acquire()
            for l in links:
                self._node_graph[l.src.dpid].neighbours[l.src.port_no] = self._node_graph[l.dst.dpid]
        finally:
            self.mutex.release()

    def _update_nodes(self, switches: List[Switch]):
        try:
            self.mutex.acquire()
            for sw in switches:
                node = Node(node_type=NodeType.OF_SWITCH, datapath=sw.dp,
                            neighbours={}, ports={port.port_no: SimplePort(port.dpid, port.port_no, port.hw_addr, 10, 0) for port in sw.ports})

                existing = self._node_graph.get(sw.dp.id)
                if existing is not None:
                    for port_no, port in existing.ports.items():
                        node.ports[port_no] = port
                self._node_graph[sw.dp.id] = node
        finally:
            self.mutex.release()

    def host_learning(self, src_mac, ipv4, dpid, in_port):
        if self._hosts.get(src_mac) is None:
            try:
                self.mutex.acquire()
                node = self._node_graph.get(dpid)
                if node is None:
                    self.logger.info(f"no node known for dpid {dpid}")
                    return

                self.logger.info(f"adding host {src_mac}")
                port = node.ports.get(in_port)
                if port is None:
                    self.logger.info(f"no port known for port {in_port}")
                    return
                h = SimpleHost(src_mac, ipv4,
                               port)
                self._hosts[src_mac] = h
            finally:
                self.mutex.release()

    def get_host(self, mac: str) -> SimpleHost:
        return self._hosts.get(mac)

    def get_node(self, dpid: int) -> Node:
        return self._node_graph.get(dpid)

    def get_route(self, src_mac: int, dst_mac: int, load: float = 0) -> List[Port]:
        # get connected switches
        src_host = self._hosts.get(src_mac)
        dst_host = self._hosts.get(dst_mac)
        if src_host is None or dst_host is None:
            return None
        src_dpid = src_host.port.dpid
        dst_dpid = dst_host.port.dpid

        path: List[SimplePort] = None
        try:
            self.mutex.acquire()
            path = self.bfs(src_dpid, dst_dpid, load)
        finally:
            self.mutex.release()
        if path is None:
            # TODO : what if hosts are on same switch?
            return None

        # add path from last switch to dst host
        path.insert(0, dst_host.port)
        for port in path:
            port.load += load
        return path

    def bfs(self, src_dpid: int, dst_dpid: int, load: float = 0) -> List[SimplePort]:
        visited: List[int] = []  # List to keep track of visited nodes.
        queue: List[int] = [src_dpid]  # Initialize a queue
        prevs: Dict[int, SimplePort] = {}  # dpid to previous port

        while queue:
            cur = queue.pop(0)
            visited.append(cur)

            for port_no, node in self._node_graph[cur].neighbours.items():
                if NodeType(node.node_type) == NodeType.OF_SWITCH \
                        and node.datapath.id not in visited \
                        and self._node_graph[cur].ports[port_no].load+load < self._node_graph[cur].ports[port_no].max_load:
                    queue.append(node.datapath.id)
                    prevs[node.datapath.id] = self._node_graph[cur].ports[port_no]
                    if node.datapath.id == dst_dpid:
                        break
            else:
                continue
            break

        target = prevs.get(dst_dpid)
        if target is None:
            return None

        path = []
        cur = dst_dpid
        while prevs.get(cur) is not None:
            path.append(prevs[cur])
            cur = prevs[cur].dpid

        return path

    def call_on_all_nodes(self, cb: Callable[[Node], None]) -> None:
        for node in self._node_graph.values():
            cb(node)

    def call_on_all_broadcast_targets(self, cb: Callable[[Datapath, int], None]) -> None:
        for datapath, port_no in self._broadcast_targets:
            cb(datapath, port_no)


class MULTIPATH_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MULTIPATH_13, self).__init__(*args, **kwargs)
        self.net_graph = NetGraph(self.logger)
        self.arp_dispatcher = ArpDispatcher(1)
        self.monitor_thread = hub.spawn(self.query_switches)

    @ set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s', msg.type, msg.code,
                          utils.hex_array(msg.data))

    @ set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
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

    def add_flow(self, datapath, hard_timeout, priority, match, actions, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst, cookie=cookie)
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

    def _handle_arp_reply(self, arp_pkt: arp.arp):
        waiting_list = self.arp_dispatcher.handle_arp_reply(
            arp_pkt.src_ip, arp_pkt.src_mac)
        self._respond_arp(arp_pkt.src_ip, arp_pkt.src_mac, waiting_list)

    def _respond_arp(self, target_ip: str, target_mac: str, dst_macs: List[str]):
        for mac in dst_macs:
            h = self.net_graph.get_host(mac)
            if h is None:
                self.logger.info(
                    f"skipping arp response to unknown target {mac}")
                continue
            dst_ip = h.ipv4

            response = packet.Packet()
            response.add_protocol(ethernet.ethernet(
                ethertype=ether.ETH_TYPE_ARP,
                src=target_mac,
                dst=mac
            ))

            response.add_protocol(arp.arp_ip(opcode=arp.ARP_REPLY,
                                             src_mac=target_mac,
                                             src_ip=target_ip,
                                             dst_mac=mac,
                                             dst_ip=dst_ip
                                             ))
            response.serialize()

            node = self.net_graph.get_node(h.port.dpid)
            if node is None:
                self.logger.info(
                    f"no node for dpid {h.port.dpid} in host {h.mac}")
                continue

            datapath = node.datapath
            ofproto = datapath.ofproto
            port_no = h.port.port_no

            self.send_packet_out(datapath, datapath.ofproto.OFP_NO_BUFFER,
                                 ofproto.OFPP_CONTROLLER, port_no, response.data)

    def _request_arp(self, target_ip: str, src_ip: str, src_mac: str):
        request = packet.Packet()
        request.add_protocol(ethernet.ethernet(
            ethertype=ether.ETH_TYPE_ARP,
            src=src_mac
        ))

        request.add_protocol(arp.arp_ip(opcode=arp.ARP_REQUEST,
                                        src_mac=src_mac,
                                        src_ip=src_ip,
                                        dst_mac="ff:ff:ff:ff:ff:ff",
                                        dst_ip=target_ip))
        request.serialize()

        def cb(datapath: Datapath, port_no: int) -> None:
            ofproto = datapath.ofproto
            self.send_packet_out(datapath, datapath.ofproto.OFP_NO_BUFFER,
                                 ofproto.OFPP_CONTROLLER, port_no, request.data)
        self.net_graph.call_on_all_broadcast_targets(cb)

    def _handle_arp_req(self, arp_pkt: arp.arp):
        mac, should_request = self.arp_dispatcher.handle_arp_request(
            arp_pkt.src_mac, arp_pkt.dst_ip)
        if mac is not None:
            self._respond_arp(arp_pkt.dst_ip, mac, [arp_pkt.src_mac])
            return
        if should_request:
            self._request_arp(arp_pkt.dst_ip, arp_pkt.src_ip, arp_pkt.src_mac)

    def _handle_arp(self, msg):
        self.logger.debug("ARP processing")

        pkt = packet.Packet(msg.data)
        arp_pkt: arp.arp = pkt.get_protocol(arp.arp)

        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        self.net_graph.host_learning(
            arp_pkt.src_mac, arp_pkt.src_ip, dpid, in_port)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            self._handle_arp_req(arp_pkt)
            return

        if arp_pkt.opcode == arp.ARP_REPLY:
            self._handle_arp_reply(arp_pkt)
            return

    def _handle_ip(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        path = self.net_graph.get_route(eth.src, eth.dst, 6)

        # try one more time because graph could have been not updated
        if path is None:
            self.update_switches()
            path = self.net_graph.get_route(eth.src, eth.dst, 6)
        if path is None:
            self.logger.info(
                "could not create path from %s to %s", eth.src, eth.dst)
            # for debug
            path = self.net_graph.get_route(eth.src, eth.dst, 6)
            return

        # add flows to all switches in route

        cookie = randint(0, UINT64_MAX)
        print(f"cookie: {cookie}")
        for path_node in path:
            actions = [parser.OFPActionOutput(path_node.port_no)]
            match = parser.OFPMatch(eth_src=eth.src,
                                    eth_dst=eth.dst, eth_type=eth.ethertype)
            dp = self.net_graph.get_node(path_node.dpid).datapath
            self.add_flow(dp, 0, 1, match, actions, cookie)
        # wait for flows to apply
        hub.sleep(0.05)

        # current switch out port
        out_port = path[-1].port_no
        # send this packet through the right port
        self.send_packet_out(datapath, msg.buffer_id, in_port,
                             out_port, msg.data)

    @ set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

        pkt = packet.Packet(msg.data)

        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        if isinstance(ip_pkt_6, ipv6.ipv6):
            self.logger.info("dropping unexpected ipv6 packet")
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if isinstance(arp_pkt, arp.arp):
            self._handle_arp(msg)
            packet.Packet(msg.data)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if isinstance(ip_pkt, ipv4.ipv4):
            self._handle_ip(msg)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == LATENCY_PROBE:
            packet.Packet(msg.data)
            print(f'receiving {pkt.protocols}')
            latency_probe_pkt = pkt.get_protocol(LatencyProbePacket)
            if isinstance(latency_probe_pkt, LatencyProbePacket):
                print(pkt)

    def query_switches(self) -> None:
        def request_stats(node: Node) -> None:
            dp = node.datapath
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            req = ofp_parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY)
            print('Sent ', req)
            dp.send_msg(req)

        def send_latency_probe(node: Node):
            datapath = node.datapath
            ofproto = datapath.ofproto

            for port_no in node.neighbours:
                probe = packet.Packet()
                probe.add_protocol(ethernet.ethernet(
                    ethertype=LATENCY_PROBE,
                    dst="11:22:33:44:55:66",
                    src="00:11:22:33:44:55"
                    # dst=node.ports[port_no].mac, #TODO: add mac to SimplePort
                ))

                probe.add_protocol(LatencyProbePacket(time.time_ns()))

                probe.serialize()

                print(f'writing {probe.protocols}')

                self.send_packet_out(datapath, datapath.ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER, port_no, probe.data)

        while True:
            hub.sleep(5)
            # self.net_graph.call_on_all_nodes(request_stats)
            self.net_graph.call_on_all_nodes(send_latency_probe)

    @ set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
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
            print(ports[-1])
            print()
        # print('PortStats: ', ports)

    @ set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        self.logger.info(f"new switch entered: {ev.switch.dp.id}")
        self.update_switches()

    def update_switches(self):
        switches = copy.copy(get_switch(self))
        links = copy.copy(get_link(self))

        self.net_graph.update_switches(switches, links)

        # self.query_ports_description() #port description has false information
