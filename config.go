package main

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/BurntSushi/toml"
)

const (
	defaultMsgSize      = 25
	defaultUpdateTimer  = 30
	defaultTimeoutTimer = 180
	defaultGarbageTimer = 120
	defaultLocalMetric  = 10
)

type tempConfig struct {
	Interfaces map[string]ifc
	Neighbors  map[string]nbrs
	Timers     timers
	Global     global
}

type config struct {
	Interfaces map[int]ifc
	Neighbors  map[uint32]nbrs
	Timers     timers
	Global     global
}

type global struct {
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

type nbrs struct {
	KeyChain keyChain
}

type keyChain struct {
	AuthType uint16
	AuthKey  string
}

func readConfig() (*config, error) {
	var tempConfig tempConfig
	var conf config
	_, err := toml.DecodeFile(sys.cfgPath, &tempConfig)
	if err != nil {
		return nil, err
	}

	conf = config{
		Global: tempConfig.Global,
		Timers: tempConfig.Timers,
	}

	conf.Interfaces = make(map[int]ifc, 0)
	conf.Neighbors = make(map[uint32]nbrs, 0)

	for ifn, param := range tempConfig.Interfaces {
		ifi, err := net.InterfaceByName(ifn)
		if err != nil {
			sys.logger.send(erro, err)
		} else {
			conf.Interfaces[ifi.Index] = param
		}
	}

	for ipn, param := range tempConfig.Neighbors {
		if net.ParseIP(ipn).To4().IsGlobalUnicast() {
			ip := binary.BigEndian.Uint32(net.ParseIP(ipn).To4())
			conf.Neighbors[ip] = param
		}
	}

	return &conf, nil
}

func (c *config) validate() error {
	if c.Global.Metric == 0 && c.Global.Metric > 255 {
		c.Global.Metric = defaultLocalMetric
		return errors.New("local metric must be in range 1-255")
	}
	if c.Global.MsgSize < 25 && c.Global.MsgSize > 255 {
		c.Global.MsgSize = defaultMsgSize
		return errors.New("Number of route entries per update message must be in range 25-255")
	}
	if c.Timers.UpdateTimer < 10 && c.Timers.UpdateTimer > 60 {
		c.Timers.UpdateTimer = defaultUpdateTimer
		return errors.New("Interval between regular route updates must be in range 10-60")
	}
	if c.Timers.TimeoutTimer < 30 && c.Timers.TimeoutTimer > 360 {
		c.Timers.TimeoutTimer = defaultTimeoutTimer
		return errors.New("Delay before routes time out must be in range 30-360")
	}
	if c.Timers.GarbageTimer < 10 && c.Timers.GarbageTimer > 180 {
		c.Timers.GarbageTimer = defaultGarbageTimer
		return errors.New("Hold-down time must be in range 10-180")
	}
	return nil
}
