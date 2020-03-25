package main

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/BurntSushi/toml"
)

const (
	defaultEntryCount   = 25
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
	Metric     int
	EntryCount int
	Log        uint8
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
	var tmpConf tempConfig
	var conf config
	if _, err := toml.DecodeFile(sys.cfgPath, &tmpConf); err != nil {
		return nil, err
	}

	conf = config{
		Global: tmpConf.Global,
		Timers: tmpConf.Timers,
	}

	conf.Interfaces = make(map[int]ifc, 0)
	conf.Neighbors = make(map[uint32]nbrs, 0)

	for ifn, param := range tmpConf.Interfaces {
		ifi, err := net.InterfaceByName(ifn)
		if err != nil {
			sys.logger.send(warn, err)
		} else {
			conf.Interfaces[ifi.Index] = param
		}
	}

	for ipn, param := range tmpConf.Neighbors {
		ip := net.ParseIP(ipn).To4()
		if ip.IsGlobalUnicast() {
			ip := binary.BigEndian.Uint32(ip)
			conf.Neighbors[ip] = param
		} else {
			sys.logger.send(warn, "unvalidated static neighbor IP "+ipn)
		}
	}

	conf.validate()

	return &conf, nil
}

func (c *config) validate() {
	if c.Global.Metric == 0 && c.Global.Metric > 255 {
		c.Global.Metric = defaultLocalMetric
		err := errors.New("local metric must be in range 1-255")
		sys.logger.send(warn, err)
	}
	if c.Global.EntryCount < 25 && c.Global.EntryCount > 255 {
		c.Global.EntryCount = defaultEntryCount
		err := errors.New("number of route entries per update message must be in range 25-255")
		sys.logger.send(warn, err)
	}
	if c.Timers.UpdateTimer < 10 && c.Timers.UpdateTimer > 60 {
		c.Timers.UpdateTimer = defaultUpdateTimer
		err := errors.New("interval between regular route updates must be in range 10-60")
		sys.logger.send(warn, err)
	}
	if c.Timers.TimeoutTimer < 30 && c.Timers.TimeoutTimer > 360 {
		c.Timers.TimeoutTimer = defaultTimeoutTimer
		err := errors.New("delay before routes time out must be in range 30-360")
		sys.logger.send(warn, err)
	}
	if c.Timers.GarbageTimer < 10 && c.Timers.GarbageTimer > 180 {
		c.Timers.GarbageTimer = defaultGarbageTimer
		err := errors.New("hold-down time must be in range 10-180")
		sys.logger.send(warn, err)
	}
}
