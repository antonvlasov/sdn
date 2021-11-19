from mininet.log import lg
from mininet.node import RemoteController
from mininet.cli import CLI
import net_topo
from net_topo.topo import topology
from mininet.topo import Topo
from mininet.net import Mininet

topo = topology()
topo.addCells(4, 9)
print(topo.sw_conns)


class ClusterTopo(Topo):
    "Simple loop topology example."

    def __init__(self):
        "Create custom loop topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        hosts = {}
        switches = {}
        for hs in topo.endpoints:
            hosts[hs[0]] = self.addHost(hs[0])
            switches[hs[1]] = self.addSwitch(hs[1])

        for edge in topo.endpoints:
            self.addLink(hosts[edge[0]], switches[edge[1]])
        for edge in topo.sw_conns:
            self.addLink(switches[edge[0]], switches[edge[1]])


topos = {'clusterTopo': (lambda: ClusterTopo())}


def StartServer(network):
    uvicorn = 'uvicorn counting_server.server:app --host {} --port 8001 &'
    for host in network.hosts:
        host.cmd(uvicorn.format(host.IP()))

    min_ip, max_ip = "", ""
    if len(network.hosts) > 0:
        min_ip = network.hosts[0].IP()
        max_ip = network.hosts[len(network.hosts)-1].IP()
    client = 'python3 -m counting_server.client -s {} -e {} &'.format(
        min_ip, max_ip)
    for host in network.hosts:
        host.cmd(client)


if __name__ == "__main__":
    lg.setLogLevel('info')
    net = Mininet(topo=ClusterTopo(), controller=RemoteController(
        'ryu', port=6653), autoSetMacs=True)
    net.start()
    # StartServer(net)
    CLI(net)
    net.stop()
