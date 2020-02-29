package main

import (
	"github.com/BurntSushi/toml"
)

const (
	settings string = "./src/github.com/n00btype/ripv2-go/setting.toml"
)

type config struct {
	Interfaces map[string]ifc
	Timers     timers
	Local      local
}

type local struct {
	Metric int
}

type timers struct {
	UpdateTimer  int64
	TimeoutTimer int64
	GarbageTimer int64
}

type ifc struct {
	Passive  bool
	Auth     bool
	Timers   timers
	KeyChain keyChain
}

type keyChain struct {
	AuthType uint16
	AuthKey  string
}

func readConfig() (*config, error) {
	var conf config
	_, err := toml.DecodeFile(settings, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
