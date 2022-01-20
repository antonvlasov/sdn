from mininet.log import lg
from mininet.node import RemoteController
from mininet.cli import CLI
from net_topo.topo import topology, CenteredTopo, CrystalTopo
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink


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


def StartServices(network, measureTimeSingleTarget: bool):
    for h in network.hosts:
        cmd = ' '.join(
            ['/home/mininet/project/host_service/host-service',
             '-port', '6000',
             '-pair.csv', '/home/mininet/project/data/scenario/pairs.csv',
             '-host-number', h.name[1:],
             '-dataflow.csv', '/home/mininet/project/data/scenario/generated/prolonged_10.csv',
             '-time-koefficient', "1",
             f'-measure-single={measureTimeSingleTarget}',
             '&'])
        res = h.cmd(cmd)
        if res != "":
            print(res)


if __name__ == "__main__":
    lg.setLogLevel('info')

    topo = topology.from_csv(
        "/home/mininet/project/data/scenario/topology.csv")

    # topo = topology()
    # topo.addCells(5, 4, 10)
    # topo = CenteredTopo(30, 1)

    #topo = CrystalTopo(10)

    net = Mininet(topo=MyTopo(topo), controller=RemoteController(
        'ryu', port=6653), autoSetMacs=True, link=TCLink)
    net.start()
    #StartServices(net, True)
    CLI(net)
    net.stop()
