from pyvis.network import Network
from net_topo.topo import topology
import os

if __name__ == "__main__":

    topo = topology()
    topo.addCells(4, 8)

    net = Network()
    net.add_nodes([hs[0] for hs in topo.endpoints],
                  size=[5 for i in range(len(topo.endpoints))])
    net.add_nodes([hs[1] for hs in topo.endpoints],
                  color=['#ff0000' for i in range(len(topo.endpoints))],
                  size=[15 for i in range(len(topo.endpoints))])
    net.add_edges(topo.endpoints)
    net.add_edges(topo.sw_conns)

    path = os.path.dirname(os.path.realpath(__file__))
    net.save_graph(path+'/net_30_sw.html')
