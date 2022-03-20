from xmlrpc.client import Boolean
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet, packet_base, ethernet, arp, ipv4, ipv6, tcp, udp, icmp
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu import utils
import yaml

from ryu.lib import hub
from typing import Callable, Dict, Optional, Any, List, Set, Tuple, final
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

import importlib.util

random.seed()

UINT64_MAX = 18446744073709551616
FLOW_COST = None
IDLE_TIMEOUT = 10

GET_BANDWIDTH = None


def init_bandwidths(cfg: Dict[str, Any]) -> Tuple[int, Callable[[int, int], int]]:
    bw = cfg['bandwidth']
    _FLOW_COST = cfg['flow-bw']/2

    def _GET_BANDWIDTH(src: int, dst: int) -> int:
        return bw

    return _FLOW_COST,  _GET_BANDWIDTH


with open("/home/mininet/project/data/cfg/topo.yaml", "r") as f:
    try:
        cfg: Dict[str, Any] = yaml.safe_load(f)
        FLOW_COST, GET_BANDWIDTH = init_bandwidths(cfg)

    except yaml.YAMLError as exc:
        print(exc)
        raise exc


class RWMutex:
    _mu: hub.BoundedSemaphore
    _sem: hub.BoundedSemaphore
    _max_readers: int

    def __init__(self, max_readers=1024) -> None:
        self._mu = hub.BoundedSemaphore(1)
        self._sem = hub.BoundedSemaphore(max_readers)
        self._max_readers = max_readers

    def r_lock(self):
        self._sem.acquire()

    def r_unlock(self):
        self._sem.release()

    def w_lock(self):
        try:
            self._mu.acquire()
            for _ in range(self._max_readers):
                self._sem.acquire()
        finally:
            self._mu.release()

    def w_unlock(self):
        for _ in range(self._max_readers):
            self._sem.release()


@dataclass
class SimplePort:
    dpid: int
    port_no: int
    mac: str
    load: int = 0
    max_load: int = 0


@dataclass
class SimpleHost:
    mac: str
    ipv4: str
    port: SimplePort


@dataclass
class Node:
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
    _mutex: RWMutex

    def __init__(self, logger) -> None:
        self.logger = logger

        self._node_graph = {}  # datapath.id to Node
        self._hosts = {}  # mac to host
        self._broadcast_targets = set()
        self._mutex = RWMutex()

    def _update_broadcast_targets(self):
        targets = set()
        for node in self._node_graph.values():
            non_switch_ports = node.ports.keys()-node.neighbours.keys()
            for port in non_switch_ports:
                targets.add((node.datapath, port))
        self._broadcast_targets = targets

    def update_switches(self, switches: List[Switch], links: List[Link]):
        try:
            self._mutex.w_lock()
            self._update_nodes(switches)
            self._update_links(links)
            self._update_broadcast_targets()
        finally:
            self._mutex.w_unlock()

        print(" \t" + "Saved Links:")
        for dpid, s in self._node_graph.items():
            for port, l in s.neighbours.items():
                print(" \t\t dpid: {}, port: {} dpid: {}".format(
                    dpid, port, l.datapath.id))
            print()

    def _update_links(self, links: List[Link]):
        for l in links:
            self._node_graph[l.src.dpid].neighbours[l.src.port_no] = self._node_graph[l.dst.dpid]
            self._node_graph[l.src.dpid].ports[l.src.port_no].max_load = GET_BANDWIDTH(
                l.src.dpid, l.dst.dpid)

    def _update_nodes(self, switches: List[Switch]):
        for sw in switches:
            node = Node(datapath=sw.dp,
                        neighbours={}, ports={port.port_no: SimplePort(port.dpid, port.port_no, port.hw_addr) for port in sw.ports})

            existing = self._node_graph.get(sw.dp.id)
            if existing is not None:
                for port_no, port in existing.ports.items():
                    node.ports[port_no] = port
            self._node_graph[sw.dp.id] = node

    def host_learning(self, src_mac, ipv4, dpid, in_port):
        if self._hosts.get(src_mac) is None:
            try:
                self._mutex.w_lock()
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
                self._mutex.w_unlock()

    def get_host(self, mac: str) -> SimpleHost:
        return self._hosts.get(mac)

    def get_node(self, dpid: int) -> Node:
        return self._node_graph.get(dpid)

    def get_route(self, src_mac: int, dst_mac: int) -> List[SimplePort]:
        try:
            self._mutex.r_lock()

            # get connected switches
            src_host = self._hosts.get(src_mac)
            dst_host = self._hosts.get(dst_mac)
            if src_host is None or dst_host is None:
                return None
            src_dpid = src_host.port.dpid
            dst_dpid = dst_host.port.dpid

            route: List[SimplePort] = self.deikstra(src_dpid, dst_dpid)
            if route is None:
                # TODO : what if hosts are on same switch?
                return None
            # add path from last switch to dst host
            route.insert(0, dst_host.port)

            return route
        finally:
            self._mutex.r_unlock()

    def deikstra(self, src_dpid: int, dst_dpid: int) -> List[SimplePort]:
        distances: Dict[int, int] = {
            node: UINT64_MAX for node in self._node_graph.keys()}
        visited: Set[int] = set()
        prevs: Dict[int, SimplePort] = {}

        distances[src_dpid] = 0

        for _ in distances:
            cur = min({node: d for node, d in distances.items() if node not in visited},
                      key=distances.get)
            visited.add(cur)
            for port_no, node in self._node_graph[cur].neighbours.items():
                if distances[cur] + self._node_graph[cur].ports[port_no].load < distances[node.datapath.id]:
                    distances[node.datapath.id] = distances[cur] + \
                        self._node_graph[cur].ports[port_no].load
                    prevs[node.datapath.id] = self._node_graph[cur].ports[port_no]

        path = []
        cur = dst_dpid
        while prevs.get(cur) is not None:
            path.append(prevs[cur])
            cur = prevs[cur].dpid

        return path

    def adjust_cost(self, route: List[SimplePort], diff):
        try:
            self._mutex.w_lock()
            for port in route:
                self._node_graph[port.dpid].ports[port.port_no].load += diff
        finally:
            self._mutex.w_unlock()

    def call_on_all_nodes(self, cb: Callable[[Node], None]) -> None:
        for node in self._node_graph.values():
            cb(node)

    def call_on_all_broadcast_targets(self, cb: Callable[[Datapath, int], None]) -> None:
        for datapath, port_no in self._broadcast_targets:
            cb(datapath, port_no)


@dataclass(frozen=True)
class SimpleMatch:
    eth_src: Any
    eth_dst: Any
    tcp_src: int
    tcp_dst: int
    udp_src: int
    udp_dst: int
    eth_type: int
    kind: str


def OFPMatch_from_SimpleMatch(match: SimpleMatch) -> OFPMatch:
    if match.kind == "tcp":
        res = OFPMatch(eth_src=match.eth_src,
                       eth_dst=match.eth_dst,
                       tcp_src=match.tcp_src,
                       tcp_dst=match.tcp_dst,
                       eth_type=match.eth_type,
                       ip_proto=6)
    elif match.kind == 'udp':
        res = OFPMatch(eth_src=match.eth_src,
                       eth_dst=match.eth_dst,
                       udp_src=match.udp_src,
                       udp_dst=match.udp_dst,
                       eth_type=match.eth_type,
                       ip_proto=17)
    else:
        res = OFPMatch(eth_src=match.eth_src,
                       eth_dst=match.eth_dst,
                       eth_type=match.eth_type)

    return res


establish_route_func = Callable[[OFPMatch, List[SimplePort], int, int], None]


class RoutingManager:
    _routes: Dict[int, Tuple[SimpleMatch, List[SimplePort]]]
    _matches: Set[SimpleMatch]
    _mu: hub.BoundedSemaphore
    _net_graph: NetGraph

    def __init__(self, net_graph):
        self._mu = hub.BoundedSemaphore()
        self._routes = {}
        self._matches = set()
        self._net_graph = net_graph

    def _establish_route(self, match: SimpleMatch, establish_route: establish_route_func) -> Boolean:
        if match not in self._matches:
            route = self._net_graph.get_route(match.eth_src, match.eth_dst)
            if route is None:
                return False

            priority = 10 if match.kind == '' else 1
            cookie = randint(0, UINT64_MAX)

            establish_route(OFPMatch_from_SimpleMatch(
                match), route, priority, cookie)

            self._net_graph.adjust_cost(route, FLOW_COST)

            self._routes[cookie] = (match, route)
            self._matches.add(match)

            t = time.localtime()
            t = time.strftime("%H:%M:%S", t)
            print(
                f"{t}: established route from {match.eth_src} port {match.tcp_src} to {match.eth_dst} port {match.tcp_dst}")

        return True

    def handle_route_request(self, forward_match: SimpleMatch, backward_match: SimpleMatch, establish_route: establish_route_func) -> Boolean:
        try:
            self._mu.acquire()
            if not self._establish_route(forward_match, establish_route):
                return False
            if not self._establish_route(backward_match, establish_route):
                return False

            return True
        finally:
            self._mu.release()

    def delete_route(self, cookie: int):
        try:
            self._mu.acquire()
            if cookie in self._routes.keys():
                match, route = self._routes[cookie]
                self._net_graph.adjust_cost(route, -FLOW_COST)
                del self._routes[cookie]
                self._matches.remove(match)

                t = time.localtime()
                t = time.strftime("%H:%M:%S", t)
                print(
                    f"{t}: deleted route from {match.eth_src} port {match.tcp_src} to {match.eth_dst} port {match.tcp_dst}")
        finally:
            self._mu.release()


class MULTIPATH_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MULTIPATH_13, self).__init__(*args, **kwargs)
        self._net_graph = NetGraph(self.logger)
        self._arp_dispatcher = ArpDispatcher(1)
        self._monitor_thread = hub.spawn(self.query_switches)
        self._routing_manager = RoutingManager(self._net_graph)

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
        self.add_flow(datapath, 0, match, actions, 0, 0)

        # ask to notify controller on every event
        self.send_set_async(datapath)

        self.logger.info("switch:%s connected", dpid)

    def send_set_async(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        packet_in_mask = 1 << ofp.OFPR_NO_MATCH | 1 << ofp.OFPR_ACTION
        port_status_mask = (1 << ofp.OFPPR_ADD
                            | 1 << ofp.OFPPR_DELETE
                            | 1 << ofp.OFPPR_MODIFY)
        flow_removed_mask = (1 << ofp.OFPRR_IDLE_TIMEOUT
                             | 1 << ofp.OFPRR_HARD_TIMEOUT
                             | 1 << ofp.OFPRR_DELETE
                             | ofp.OFPRR_GROUP_DELETE)
        req = ofp_parser.OFPSetAsync(datapath,
                                     [packet_in_mask, packet_in_mask],
                                     [port_status_mask, port_status_mask],
                                     [flow_removed_mask, flow_removed_mask])
        datapath.send_msg(req)

    def add_flow(self, datapath, priority, match, actions, idle_timeout: int, cookie: int):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                idle_timeout=idle_timeout,
                                flags=ofp.OFPFF_SEND_FLOW_REM,
                                cookie=cookie)
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
        waiting_list = self._arp_dispatcher.handle_arp_reply(
            arp_pkt.src_ip, arp_pkt.src_mac)
        self._respond_arp(arp_pkt.src_ip, arp_pkt.src_mac, waiting_list)

    def _respond_arp(self, target_ip: str, target_mac: str, dst_macs: List[str]):
        for mac in dst_macs:
            h = self._net_graph.get_host(mac)
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

            node = self._net_graph.get_node(h.port.dpid)
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
        self._net_graph.call_on_all_broadcast_targets(cb)

    def _handle_arp_req(self, arp_pkt: arp.arp):
        mac, should_request = self._arp_dispatcher.handle_arp_request(
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

        self._net_graph.host_learning(
            arp_pkt.src_mac, arp_pkt.src_ip, dpid, in_port)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            self._handle_arp_req(arp_pkt)
            return

        if arp_pkt.opcode == arp.ARP_REPLY:
            self._handle_arp_reply(arp_pkt)
            return

    def _establish_route(self, parser, match, route: List[SimplePort], priority: int, cookie: int):
        # send flows to controller
        for path_node in route:
            cp_match = copy.copy(match)
            actions = [parser.OFPActionOutput(path_node.port_no)]
            dp = self._net_graph.get_node(path_node.dpid).datapath

            # TODO: add idle timeout and notify controller on flow removal to substract cost from internal graph

            self.add_flow(dp, priority, cp_match,
                          actions, IDLE_TIMEOUT, cookie)

    def _create_matches(self, pkt: packet.Packet) -> Tuple[SimpleMatch, SimpleMatch, OFPMatch, OFPMatch]:
        eth: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)
        tcp_pkt: tcp.tcp = pkt.get_protocol(tcp.tcp)
        udp_pkt: udp.udp = pkt.get_protocol(udp.udp)

        fwd_simple_match = None
        bwd_simple_match = None
        if isinstance(tcp_pkt, tcp.tcp):
            fwd_simple_match = SimpleMatch(
                eth.src, eth.dst, tcp_pkt.src_port, tcp_pkt.dst_port, 0, 0, eth.ethertype, 'tcp')
            bwd_simple_match = SimpleMatch(
                eth.dst, eth.src, tcp_pkt.dst_port, tcp_pkt.src_port, 0, 0, eth.ethertype, 'tcp')
        elif isinstance(udp_pkt, udp.udp):
            fwd_simple_match = SimpleMatch(
                eth.src, eth.dst, 0, 0, udp_pkt.src_port, udp_pkt.dst_port, eth.ethertype, 'udp')
            bwd_simple_match = SimpleMatch(
                eth.dst, eth.src, 0, 0, udp_pkt.dst_port, udp_pkt.src_port, eth.ethertype, 'udp')
        else:
            fwd_simple_match = SimpleMatch(
                eth.src, eth.dst, 0, 0, 0, 0, eth.ethertype, '')
            bwd_simple_match = SimpleMatch(
                eth.dst, eth.src, 0, 0, 0, 0, eth.ethertype, '')

        return fwd_simple_match, bwd_simple_match

    def _handle_ip(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)

        matches = self._create_matches(pkt)
        if matches is None:
            return

        def er(match: OFPMatch, route: List[SimplePort], priority: int, cookie: int):
            self._establish_route(parser, match, route, priority, cookie)

        if not self._routing_manager.handle_route_request(matches[0], matches[1], er):
            # try one more time because graph could have been not updated
            self.update_switches()
            if not self._routing_manager.handle_route_request(matches[0], matches[1], er):
                # we are done
                self.logger.info(
                    "could not create route from %s to %s", matches[0].eth_src, matches[0].eth_dst)
                return

        # send this packet back to switch and let it match newly added rules
        ofproto = datapath.ofproto
        self.send_packet_out(datapath, msg.buffer_id,
                             ofproto.OFPP_CONTROLLER, ofproto.OFPP_TABLE, msg.data)

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

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            self._routing_manager.delete_route(msg.cookie)
        else:
            self.logger.info(f"unexpected route remove reason: {msg.reason}")

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
            # self.net_graph.call_on_all_nodes(send_latency_probe)

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

        self._net_graph.update_switches(switches, links)

        # self.query_ports_description() #port description has false information
