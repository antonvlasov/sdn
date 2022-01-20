import csv
import pandas as pd
import numpy as np


class topology:
    def __init__(self):
        self.endpoints = []
        self.sw_conns = []

    def addEndpoint(self):
        h = 'h{}'.format(len(self.endpoints)+1)
        s = 's{}'.format(len(self.endpoints)+1)
        self.endpoints.append((h, s))

    def addEndpointCell(self, size, bandwidth):
        for i in range(size):
            self.addEndpoint()
        for i in range(len(self.endpoints)-size, len(self.endpoints)):
            for j in range(i+1, len(self.endpoints)):
                self.sw_conns.append(
                    (self.endpoints[i][1], self.endpoints[j][1], bandwidth))

    def addCells(self, cellSize, cellCount, bandwidth):
        for i in range(cellCount):
            self.addEndpointCell(cellSize, bandwidth)
        for i in range(1, cellCount):
            self.sw_conns.append(
                (self.endpoints[(i-1)*cellSize][1], self.endpoints[i*cellSize][1]))
        if cellCount > 2:
            self.sw_conns.append(
                (self.endpoints[0][1], self.endpoints[-1][1], bandwidth))

    @classmethod
    def from_csv(cls, path, parts=1):
        res = cls()

        df = pd.read_csv(path, sep=';', dtype=int)
        df = df.iloc[:len(df)//parts, :len(df)//parts]
        print(df)
        matrix = df.to_numpy()
        if len(matrix) < 2:
            raise Exception("bad matrix len < 2")
        if len(matrix[0]) != len(matrix):
            raise Exception("not square matrix")

        for _ in matrix:
            res.addEndpoint()
        for i in range(len(matrix)):
            cols = np.where(matrix[i][:len(matrix[i])] != 0)
            print(cols[0])
            cols = [col for col in cols[0] if col > i]
            print(cols)
            for col in cols:
                res.sw_conns.append((
                    res.endpoints[i][1], res.endpoints[col][1], matrix[i][col]))
        return res


class CenteredTopo:
    def __init__(self, count, bandwidth):
        self.endpoints = []
        self.sw_conns = []

        center = ('h1', 's1')
        self.endpoints.append(center)
        for i in range(2, count+2):
            leaf = (f'h{i}', f's{i}')
            self.endpoints.append(leaf)
            self.sw_conns.append((center[1], leaf[1], bandwidth))


class CrystalTopo:
    def __init__(self, bandwidth):
        self.endpoints = []
        self.sw_conns = []

        left = ('h1', 's1')
        tl = ('h2', 's2')
        bl = ('h3', 's3')
        tr = ('h4', 's4')
        br = ('h5', 's5')
        right = ('h6', 's6')

        self.endpoints = [left, tl, bl, tr, br, right]

        self.sw_conns = [
            (left[1], tl[1], bandwidth),
            (left[1], bl[1], bandwidth),
            (tl[1], bl[1], bandwidth),
            (tl[1], tr[1], bandwidth),
            (tl[1], br[1], bandwidth),
            (bl[1], tr[1], bandwidth),
            (bl[1], br[1], bandwidth),
            (tr[1], br[1], bandwidth),
            (tr[1], right[1], bandwidth),
            (br[1], right[1], bandwidth)
        ]

        # end = len(self.sw_conns)
        # i = 0
        # while i < end:
        #     self.sw_conns.append(
        #         (self.sw_conns[i][1], self.sw_conns[i][0], bandwidth))
        #     i += 1


if __name__ == "__main__":
    topo = CrystalTopo(10)
    print(topo.endpoints)
    print(topo.sw_conns)

    # topo = topology.from_csv(
    #     "/home/mininet/project/data/scenario/topology.csv")
    # print(topo.endpoints)
    # print(topo.sw_conns)
