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
                (self.endpoints[0][1], self.endpoints[len(self.endpoints)-1][1]))
