from mininet.log import lg
from mininet.node import RemoteController
from mininet.cli import CLI
from net_topo.topo import topology
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink

from analytics.post_model import check_no_packets_dropped

import time
import yaml
from typing import Dict, Any, Tuple
import os
import subprocess
import posix_ipc
from datetime import datetime

SEMAPHORE_NAME = '/mininet_host_clients'


class MyTopo(Topo):

    def __init__(self, topo: topology, bw: float = None):

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        hosts = {}
        switches = {}
        for hs in topo.endpoints:
            hosts[hs[0]] = self.addHost(hs[0])
            switches[hs[1]] = self.addSwitch(hs[1])

        for edge in topo.endpoints:
            self.addLink(hosts[edge[0]], switches[edge[1]],
                         cls=TCLink, bw=bw)
        for edge in topo.sw_conns:
            self.addLink(switches[edge[0]],
                         switches[edge[1]], cls=TCLink, bw=bw)


def StartServices(network, semaphore, test_name, flow_bw, binary, scenario_folder):
    print('starting services')
    for h in network.hosts:
        cmd = ' '.join(
            [binary,
             '--scenario', os.path.join(scenario_folder, h.name+'.json'),
             '--sem-name', semaphore.name,
             '--test-name', test_name,
             '--flow-bw', flow_bw,
             '&'])

        semaphore.release()

        res = h.cmd(cmd)
        if res != "":
            print(res)


def retrieve_services_settings(cfg: Dict[str, Any]):
    services: Dict[str, Any] = cfg.get('services')
    if services is None:
        return None

    binary = services['binary']
    scenario_folder = services['scenario-folder']

    return binary, scenario_folder


def init_topo(cfg: Dict[str, Any]):
    if cfg.get('csv') is not None:
        return topology.from_csv(cfg['csv'])

    if cfg['kind'] == 'crystal':
        return topology.crystal()

    if cfg['kind'] == 'cells':
        topo = topology()
        topo.addCells(int(cfg['cell-size']), cfg['cell-count'])
        return topo

    if cfg['kind'] == 'jellyfish':
        return topology.jellyfish(int(cfg['nodes']), int(cfg['connectivity']), int(cfg['seed']))

    if cfg['kind'] == 'simplest':
        return topology.simplest_of_topologies()

    raise Exception('unexpected topo kind')


def main():
    lg.setLogLevel('info')

    # parse config
    topo = None
    bandwidth = None
    services_setting = None
    manual = False
    launch_controller = False
    flow_bw = None
    with open("/home/mininet/project/data/cfg/topo.yaml", "r") as f:
        try:
            cfg: Dict[str, Any] = yaml.safe_load(f)
            topo = init_topo(cfg['topo'])
            bandwidth = cfg.get('bandwidth')
            services_setting = retrieve_services_settings(cfg)
            manual = cfg.setdefault('manual', False)
            launch_controller = cfg.setdefault('launch-controller', False)
            flow_bw = str(cfg['flow-bw'])

        except yaml.YAMLError as exc:
            print(exc)
            raise exc

    # start controller

    pcontroller = None
    if launch_controller:
        print("starting ryu controller...")
        pcontroller = subprocess.Popen(["python", "-m", "controller.ryu-controller"],
                                       cwd='/home/mininet/project/', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # start model

    net = Mininet(topo=MyTopo(topo, bandwidth), controller=RemoteController(
        'ryu', port=6653), autoSetMacs=True, link=TCLink)
    net.start()

    test_name = datetime.now().strftime('%Y-%m-%d::%H:%M:%S:%f')
    print(test_name)

    if services_setting is not None:
        sem = posix_ipc.Semaphore(SEMAPHORE_NAME, flags=posix_ipc.O_CREX)
        StartServices(net, sem, test_name, flow_bw, *services_setting)

        if manual:
            CLI(net)
        else:
            while True:
                time.sleep(1)
                if sem.value == 0:
                    break
            sem.unlink()
    else:
        CLI(net)

    # cleanup
    net.stop()

    if pcontroller is not None:
        pcontroller.kill()
        print("sent kill to controller")

    # check connectivity
    check_no_packets_dropped()


if __name__ == "__main__":
    main()
