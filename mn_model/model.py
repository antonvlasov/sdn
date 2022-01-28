from time import time
from mininet.log import lg
from mininet.node import RemoteController
from mininet.cli import CLI
from net_topo.topo import topology
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
import yaml
from typing import Dict, Any, Tuple


class MyTopo(Topo):

    def __init__(self, topo: topology):

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        hosts = {}
        switches = {}
        for hs in topo.endpoints:
            hosts[hs[0]] = self.addHost(hs[0])
            switches[hs[1]] = self.addSwitch(hs[1])

        for edge in topo.endpoints:
            self.addLink(hosts[edge[0]], switches[edge[1]], cls=TCLink)
        for edge in topo.sw_conns:
            self.addLink(switches[edge[0]],
                         switches[edge[1]], cls=TCLink)


def StartServices(network, port, pair_csv, dataflow_csv, time_k):
    print('starting services')
    for h in network.hosts:
        cmd = ' '.join(
            ['/home/mininet/project/host_service/host-service',
             '-port', port,
             '-pair.csv', pair_csv,
             '-host-number', h.name[1:],
             '-dataflow.csv', dataflow_csv,
             '-time-koefficient', time_k,
             '&'])
        res = h.cmd(cmd)
        if res != "":
            print(res)


def retrieve_services_settings(cfg: Dict[str, Any]) -> Tuple[str, str, str, str]:
    services: Dict[str, Any] = cfg.get('services')
    if services is None:
        return None

    port = str(services['port'])
    time_k = str(services.setdefault('time-koefficient', 1))

    if services.get('pair-csv') is not None:
        pair_csv = services['pair-csv']
        dataflow_csv = services['dataflow-csv']
        return port, pair_csv, dataflow_csv, time_k

    raise Exception('unexpected services settings')


def init_topo(cfg: Dict[str, Any]):
    if cfg.get('csv') is not None:
        return topology.from_csv(cfg['csv'])

    if cfg['kind'] == 'crystal':
        return topology.crystal()

    if cfg['kind'] == 'cells':
        topo = topology()
        topo.addCells(int(cfg['cell-size']), cfg['cell-count'])
        return topo

    raise Exception('unexpected topo kind')


if __name__ == "__main__":
    lg.setLogLevel('info')

    topo = None
    services_setting = None
    with open("/home/mininet/project/data/cfg/topo.yaml", "r") as f:
        try:
            cfg: Dict[str, Any] = yaml.safe_load(f)
            topo = init_topo(cfg['topo'])
            services_setting = retrieve_services_settings(cfg)

        except yaml.YAMLError as exc:
            print(exc)
            raise exc

    net = Mininet(topo=MyTopo(topo), controller=RemoteController(
        'ryu', port=6653), autoSetMacs=True, link=TCLink)
    net.start()

    if services_setting is not None:
        StartServices(net, *services_setting)

    CLI(net)
    net.stop()
