package service

func RunService(port int, pairPath, hostNumber, dataflowPath string, timeKoefficient float64) error {
	go func() {
		if err := RunServer(port, pairPath, hostNumber, dataflowPath); err != nil {
			panic(err)
		}
	}()

	if err := RunClient(port, pairPath, hostNumber, dataflowPath, timeKoefficient); err != nil {
		panic(err)
	}
	select {}
}
