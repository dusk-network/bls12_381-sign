package bls

func SwitchToCgo() {
	panic("does not run on windows due to no unix domain sockets")
}

func SwitchToIPC() {
	panic("does not run on windows due to no unix domain sockets")
}
