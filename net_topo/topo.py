import csv
import pandas as pd
import numpy as np
import random


class topology:
    def __init__(self):
        self.endpoints = []
        self.sw_conns = []

    def addEndpoint(self):
        h = 'h{}'.format(len(self.endpoints)+1)
        s = 's{}'.format(len(self.endpoints)+1)
        self.endpoints.append((h, s))

    def addEndpointCell(self, size):
        for i in range(size):
            self.addEndpoint()
        for i in range(len(self.endpoints)-size, len(self.endpoints)):
            for j in range(i+1, len(self.endpoints)):
                self.sw_conns.append(
                    (self.endpoints[i][1], self.endpoints[j][1]))

    def addCells(self, cellSize, cellCount):
        for i in range(cellCount):
            self.addEndpointCell(cellSize)
        for i in range(1, cellCount):
            self.sw_conns.append(
                (self.endpoints[(i-1)*cellSize][1], self.endpoints[i*cellSize][1]))
        if cellCount > 2:
            self.sw_conns.append(
                (self.endpoints[0][1], self.endpoints[-1][1]))

    @classmethod
    def from_csv(cls, path):
        res = cls()

        df = pd.read_csv(path, sep=';', dtype=int)
        matrix = df.to_numpy()
        if len(matrix) < 2:
            raise Exception("bad matrix len < 2")
        if len(matrix[0]) != len(matrix):
            raise Exception("not square matrix")

        for _ in matrix:
            res.addEndpoint()
        for i in range(len(matrix)):
            cols = np.where(matrix[i] != 0)
            for col in cols[0]:
                res.sw_conns.append((
                    res.endpoints[i][1], res.endpoints[col][1], matrix[i][col]))
        return res

    @classmethod
    def crystal(cls):
        res = cls()

        res.endpoints = []
        res.sw_conns = []

        left = ('h1', 's1')
        tl = ('h2', 's2')
        bl = ('h3', 's3')
        tr = ('h4', 's4')
        br = ('h5', 's5')
        right = ('h6', 's6')

        res.endpoints = [left, tl, bl, tr, br, right]

        res.sw_conns = [
            (left[1], tl[1]),
            (left[1], bl[1]),
            (tl[1], bl[1]),
            (tl[1], tr[1]),
            (tl[1], br[1]),
            (bl[1], tr[1]),
            (bl[1], br[1]),
            (tr[1], br[1]),
            (tr[1], right[1]),
            (br[1], right[1])
        ]

        return res

    @classmethod
    def jellyfish(cls, nodes, connectivity, seed):
        # validate
        if nodes <= connectivity:
            raise Exception("nodes<=connectivity")
        if nodes < 2:
            raise Exception("nodes<2")

        # init vars
        res = cls()
        rng = random.Random(seed)
        connections = {i: []for i in range(connectivity+1)}
        connections[0] = [i for i in range(0, nodes)]

        for i in range(nodes):
            h = 'h{}'.format(i+1)
            s = 's{}'.format(i+1)
            res.endpoints.append((h, s))

        # connect first node
        host_a = 0
        host_b = rng.randint(1, nodes)
        res.sw_conns.append((
            res.endpoints[host_a][1], res.endpoints[host_b][1]))
        connections[0].remove(host_a)
        connections[0].remove(host_b)
        connections[1].append(host_a)
        connections[1].append(host_b)

        # connect other nodes
        while True:
            host_a = None
            host_b = None
            # select one node, prefer already connected
            for i in range(1, connectivity):
                if len(connections[i]) > 0:
                    host_a = connections[i][rng.randint(
                        0, len(connections[i])-1)]
                    connections[i].remove(host_a)
                    connections[i+1].append(host_a)
                    break

            for i in range(connectivity):
                if len(connections[i]) > 0:
                    while True:
                        host_b = connections[i][rng.randint(
                            0, len(connections[i])-1)]
                        if host_b != host_a:
                            connections[i].remove(host_b)
                            connections[i+1].append(host_b)
                            break
                    break

            res.sw_conns.append((
                res.endpoints[host_a][1], res.endpoints[host_b][1]))

            if len(connections[connectivity]) == nodes:
                break

        return res

    @classmethod
    def simplest_of_topologies(cls):
        res = cls()

        res.endpoints = [('h1', 's1'), ('h2', 's2')]
        res.sw_conns = [(res.endpoints[0][1], res.endpoints[1][1])]

        return res


if __name__ == "__main__":
    topo = topology.jellyfish(16, 3, 2012)
    # print(topo.endpoints)
    print(topo.sw_conns)

    # topo = topology.from_csv(
    #     "/home/mininet/project/data/scenario/topology.csv")
