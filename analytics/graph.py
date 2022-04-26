from xmlrpc.client import Boolean
from PIL import Image
import os
import matplotlib.pyplot as plt
import networkx as nx
import dill
from typing import Dict, List, Set, Tuple
from controller.dynamic_routing import SimplePort, Node
from ryu.controller.controller import Datapath
from random import randint
from collections import namedtuple
import numpy as np

COLOR_GROUPS = 15

PortLoad = namedtuple('PortLoad', ['name', 'load', 'max_load'])
SNAPSHOT_DIR = "/home/mininet/project/data/snaps/"
ANIMATION_DIR = '/home/mininet/project/data/animations/'


def create_crystal_pos():
    switch_pos = {
        1: [-0.8, 0],
        2: [-0.4, 0.4],
        3: [-0.4, -0.4],
        4: [0.4, 0.4],
        5: [0.4, -0.4],
        6: [0.8, 0]
    }
    d = 0.15

    crystal_pos = {}

    for i in switch_pos.keys():
        for j in switch_pos.keys():
            if i == j:
                continue
            port = f'p{i}_{j}'
            v = np.subtract(switch_pos[j], switch_pos[i])
            norm_vec = v/np.sqrt(np.sum(v**2))  # v must not be zero
            stride = norm_vec*d

            crystal_pos[port] = np.add(switch_pos[i], stride)

    for k, v in switch_pos.items():
        crystal_pos[f's{k}'] = v

    return crystal_pos


crystal_pos = create_crystal_pos()


class CustomUnpickler(dill.Unpickler):
    def find_class(self, module, name):
        if name == 'Node':
            return Node
        if name == 'SimplePort':
            return SimplePort
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
    KOEF = 0.9
    idx = int(port.load/(port.max_load*KOEF)*len(groups_by_load))
    if idx >= len(groups_by_load):
        idx = len(groups_by_load)-1
    groups_by_load[idx][0].add(port.name)


def update_graph(g: nx.Graph, node_graph: Dict[int, Node]) -> Boolean:
    if len(node_graph) == 0:
        return False
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
            if len(node.ports) > 0 and node.ports[1].dpid not in visited:
                dst_dpid = node.ports[1].dpid
                dst_port_no = [
                    port_no for port_no in node.neighbours if node.neighbours[port_no].ports[1].dpid == cur][0]
                fwd_port = f'p{cur}_{dst_dpid}'
                distribute_by_load(
                    ports, PortLoad(fwd_port, node_graph[cur].ports[port_no].load, node_graph[cur].ports[port_no].max_load))
                sw_port_links.add((f's{cur}', fwd_port))

                switches.add(f's{dst_dpid}')
                bwd_port = f'p{dst_dpid}_{cur}'
                distribute_by_load(
                    ports, PortLoad(bwd_port, node_graph[dst_dpid].ports[dst_port_no].load, node_graph[dst_dpid].ports[dst_port_no].max_load))
                sw_port_links.add(
                    (f's{node.ports[1].dpid}', bwd_port))

                port_port_links.add((fwd_port, bwd_port))

                queue.append(node.ports[1].dpid)

    g.add_nodes_from(switches)
    for group in ports:
        g.add_nodes_from(group[0])
    g.add_edges_from(sw_port_links)
    g.add_edges_from(port_port_links)

    pos = None
    if len(node_graph) == 6:
        pos = crystal_pos
    else:
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

    return True


def fig2img(fig):
    """Convert a Matplotlib figure to a PIL Image and return it"""
    import io
    buf = io.BytesIO()
    fig.savefig(buf)
    buf.seek(0)
    img = Image.open(buf)
    return img


def get_stats(node_graph: Dict[int, Node]) -> Tuple[np.array, np.array]:
    loads = []
    free = []
    for node in node_graph.values():
        loads.extend([port.load for port in node.ports.values()])
        free.extend([port.max_load-port.load for port in node.ports.values()])
    loads = np.array(loads)
    free = np.array(free)

    return loads, free


def draw_boxplot(stat_snapshots: Tuple[np.array, np.array], boxplot: str):
    max1 = 0
    max2 = 0
    for s in stat_snapshots:
        if len(s[0]) > 0:
            max1 = max(max1, s[0].max())
        if len(s[1]) > 0:
            max2 = max(max2, s[1].max())

    boxplot_imgs = []

    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.tick_params(axis='both', which='major', labelsize=14)

    for i, s in enumerate(stat_snapshots):
        ax.boxplot(s)
        plt.title(str(float(i)/2.0) + 's')
        fig.subplots_adjust(left=0.15)
        ax.set_xticklabels(['load', 'free'])
        ax.set_ylabel('MBit/s')

        boxplot_imgs.append(fig2img(fig))
        ax.cla()

    boxplot_imgs[0].save(fp=boxplot, format='GIF',
                         append_images=boxplot_imgs[1:], save_all=True, duration=300, loop=0)
    plt.cla()


def mean(stat_snapshots: Tuple[np.array, np.array], mean_path: str):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.set_ylabel('MBit/s')
    ax.set_xlabel('time, s')
    ax.set_title('Load')

    ax.plot(np.linspace(0, float(len(stat_snapshots))/2.0,
                        num=len(stat_snapshots)), [s[0].mean() for s in stat_snapshots], color='red', label='load')
    plt.savefig(mean_path)
    plt.cla()


def create_analytics(snapshots_path: str, dst_folder: str):
    g = nx.Graph()
    count = len(os.listdir(snapshots_path))
    imgs: List[Image.Image] = []

    stat_snapshots = []

    for i in range(count):
        node_graph = CustomUnpickler(
            open(os.path.join(snapshots_path, str(i)), 'rb')).load()

        loads, free = get_stats(node_graph)
        stat_snapshots.append((loads, free))

        not_empty = update_graph(g, node_graph)
        if not not_empty:
            continue

        fig = plt.gcf()
        imgs.append(fig2img(fig))
        plt.clf()

    if len(imgs) == 0:
        print("no images")
        return

    draw_boxplot(stat_snapshots, os.path.join(dst_folder, 'boxplot.gif'))
    mean(stat_snapshots, os.path.join(dst_folder, 'mean.png'))

    imgs[0].save(fp=os.path.join(dst_folder, 'load.gif'), format='GIF', append_images=imgs[1:],
                 save_all=True, duration=300, loop=0)


if __name__ == "__main__":
    create_analytics(SNAPSHOT_DIR, os.path.join(ANIMATION_DIR, 'exp1'))
