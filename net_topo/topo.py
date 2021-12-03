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


if __name__ == "__main__":
    topo = topology.from_csv("/home/mininet/project/data/topology.csv")
    print(topo.endpoints)
    print(topo.sw_conns)
