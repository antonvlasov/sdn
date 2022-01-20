package service

var RandomID string

func RunService(port int, pairPath, hostNumber, dataflowPath string, timeKoefficient float64, measureTimeOnSingle bool, randomID string, testOnLocalhost bool) error {
	RandomID = randomID

	go func() {
		if err := RunServer(port, pairPath, hostNumber, dataflowPath); err != nil {
			panic(err)
		}
	}()

	if err := RunClient(port, pairPath, hostNumber, dataflowPath, timeKoefficient, measureTimeOnSingle, testOnLocalhost); err != nil {
		panic(err)
	}
	select {}
}
