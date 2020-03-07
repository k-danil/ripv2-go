package main

import (
	"errors"

	"github.com/BurntSushi/toml"
)

const (
	defaultMsgSize      = 25
	defaultUpdateTimer  = 30
	defaultTimeoutTimer = 180
	defaultGarbageTimer = 120
	defaultLocalMetric  = 10
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

func (c *config) validate() error {
	if c.Local.Metric == 0 && c.Local.Metric > 255 {
		c.Local.Metric = defaultLocalMetric
		return errors.New("local metric must be in range 1-255")
	}
	if c.Local.MsgSize < 25 && c.Local.MsgSize > 255 {
		c.Local.MsgSize = defaultMsgSize
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
