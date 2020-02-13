package main

type adj struct {
	ip      uint32
	mask    uint32
	gw      uint32
	ifi     uint16
	metric  uint8
	timeout uint8
	change  bool
}

type adjTable struct {
	entry map[uint64]adj
}
