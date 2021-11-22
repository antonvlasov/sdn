package service

func RunService(port int, commandFile string, targets []string) error {
	go func() {
		if err := RunServer(port); err != nil {
			panic(err)
		}
	}()

	if err := RunClient(commandFile, targets); err != nil {
		panic(err)
	}
	return nil
}
