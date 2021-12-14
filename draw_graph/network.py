from collections import namedtuple
from random import randint, random
from controller.dynamic_routing import SimplePort, NodeType, Node
from ryu.controller.controller import Datapath
from typing import Dict, List, Set, Tuple
import dill
import networkx as nx
import matplotlib.pyplot as plt
import os
import tempfile
from PIL import Image

COLOR_GROUPS = 10

PortLoad = namedtuple('PortLoad', ['name', 'load', 'max_load'])
SNAPSHOT_DIR = '/home/mininet/project/data/snaps'
ANIMATION_DIR = '/home/mininet/project/data/animations/'


class CustomUnpickler(dill.Unpickler):
    def find_class(self, module, name):
        if name == 'Node':
            return Node
        if name == 'SimplePort':
            return SimplePort
        if name == 'NodeType':
            return NodeType
        if name == 'Datapath':
            return Datapath
        return super().find_class(module, name)


def create_groups(group_count: int) -> List[Tuple[Set, str]]:
    res = []
    step = 255/(group_count-1)
    for i in range(group_count):
        r = f'{int(step*i):X}'.zfill(2)
        g = f'{int(255-step*i):X}'.zfill(2)
        res.append((set(), f'#{r}{g}00'))
    return res


def distribute_by_load(groups_by_load: List[Tuple[Set[str], str]], port: PortLoad):
    '''
    list tuple: set of ports; max_load
    '''
    idx = int(port.load/port.max_load*len(groups_by_load))
    if idx >= len(groups_by_load):
        idx = len(groups_by_load)-1
    groups_by_load[idx][0].add(port.name)


def update_graph(g: nx.Graph, node_graph: Dict[int, Node]):
    if len(node_graph) == 0:
        return

    visited: List[int] = []  # List to keep track of visited nodes.
    queue: List[int] = [list(node_graph)[0]]  # Initialize a queue

    switches = set()
    ports = create_groups(COLOR_GROUPS)
    sw_port_links = set()
    port_port_links = set()

    while queue:
        cur = queue.pop(0)
        visited.append(cur)
        switches.add(f's{cur}')

        for port_no, node in node_graph[cur].neighbours.items():
            if NodeType(node.node_type) == NodeType.OF_SWITCH \
                    and node._id not in visited:
                dst_port_no = [
                    port_no for port_no in node.neighbours if node.neighbours[port_no]._id == cur][0]
                distribute_by_load(
                    ports, PortLoad(f'p{cur}_{port_no}', node_graph[cur].ports[port_no].load, node_graph[cur].ports[port_no].max_load))
                sw_port_links.add((f's{cur}', f'p{cur}_{port_no}'))

                switches.add(f's{node._id}')
                distribute_by_load(
                    ports, PortLoad(f'p{node._id}_{dst_port_no}', node_graph[node._id].ports[dst_port_no].load, node_graph[node._id].ports[dst_port_no].max_load))
                sw_port_links.add(
                    (f's{node._id}', f'p{node._id}_{dst_port_no}'))

                port_port_links.add(
                    (f'p{node._id}_{dst_port_no}', f'p{cur}_{port_no}'))

                queue.append(node._id)

    g.add_nodes_from(switches)
    for group in ports:
        g.add_nodes_from(group[0])
    g.add_edges_from(sw_port_links)
    g.add_edges_from(port_port_links)
    pos = nx.spring_layout(g, seed=1)

    nx.draw_networkx_nodes(g, pos, nodelist=switches, node_size=500,
                           node_shape='s', node_color='#DCDCDC')
    for group in ports:
        nx.draw_networkx_nodes(g, pos, nodelist=group[0], node_size=100,
                               node_shape='o', node_color=group[1])
    nx.draw_networkx_edges(g, pos, edgelist=sw_port_links,
                           edge_color='#DCDCDC')
    nx.draw_networkx_edges(g, pos, edgelist=port_port_links,
                           edge_color='#0000FF')
    nx.draw_networkx_labels(g, pos)


def fig2img(fig):
    """Convert a Matplotlib figure to a PIL Image and return it"""
    import io
    buf = io.BytesIO()
    fig.savefig(buf)
    buf.seek(0)
    img = Image.open(buf)
    return img


def make_gif(snapshots_path: str, dst: str, randomize=False):
    g = nx.Graph()
    count = len(os.listdir(snapshots_path))
    imgs: List[Image.Image] = []
    for i in range(count):
        node_graph = CustomUnpickler(
            open(os.path.join(snapshots_path, str(i)), 'rb')).load()
        if randomize:
            randomize_load(node_graph)
        update_graph(g, node_graph)

        fig = plt.gcf()
        imgs.append(fig2img(fig))
        plt.clf()

    if len(imgs) == 0:
        print("no images")
        return
    imgs[0].save(fp=dst, format='GIF', append_images=imgs[1:],
                 save_all=True, duration=200, loop=0)


def randomize_load(node_graph: Dict[int, Node]):
    for node in node_graph.values():
        for port in node.ports.values():
            port.max_load = 10
            port.load = randint(0, 10)


if __name__ == "__main__":
    make_gif(SNAPSHOT_DIR,
             os.path.join(ANIMATION_DIR, 'load_large.gif'))
