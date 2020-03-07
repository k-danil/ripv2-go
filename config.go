package main

import (
	"github.com/BurntSushi/toml"
)

type config struct {
	Interfaces map[string]ifc
	Timers     timers
	Local      local
}

type local struct {
	Metric  int
	MsgSize int
	Log     uint8
}

type timers struct {
	UpdateTimer  int64
	TimeoutTimer int64
	GarbageTimer int64
}

type ifc struct {
	Passive  bool
	KeyChain keyChain
}

type keyChain struct {
	AuthType uint16
	AuthKey  string
}

func readConfig() (*config, error) {
	var conf config
	_, err := toml.DecodeFile(sys.cfgPath, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
