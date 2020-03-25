package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

const (
	user uint8 = iota
	fatal
	erro
	warn
	info
	debug
)

type logger chan<- logEntry

type logEntry struct {
	level   uint8
	message string
}

func logProcess() chan<- logEntry {
	logChan := make(chan logEntry, 4)

	go func() {
		levels := []string{
			"user",
			"fatal",
			"error",
			"warn",
			"info",
			"debug",
		}
		for l := range logChan {
			var cLevel uint8
			if sys.config != nil {
				cLevel = sys.config.Global.Log
			} else {
				cLevel = debug
			}

			msg := fmt.Sprintf("[%v] %v", levels[l.level], l.message)

			if l.level <= cLevel {
				log.Printf(msg)
			}
		}
	}()

	return logChan
}

func (l logger) send(lv uint8, msg interface{}) {
	switch msg.(type) {
	case error:
		l <- logEntry{lv, msg.(error).Error()}
		if lv == fatal {
			time.Sleep(100 * time.Millisecond)
			os.Exit(1)
		}
	case string:
		l <- logEntry{lv, msg.(string)}
	case *pdu:
		m := fmt.Sprintf("%+v\n", msg)
		l <- logEntry{lv, m}
	case map[ipNet]*adj:
		m := "Adjustments:\n"
		for ip, opt := range msg.(map[ipNet]*adj) {
			m += fmt.Sprintf("%v %s\n", ip, opt)
		}
		l <- logEntry{lv, m}
	case map[uint32]*nbr:
		m := "Neighbors:\n"
		for ip, opt := range msg.(map[uint32]*nbr) {
			m += fmt.Sprintf("%v\t%s\n", uintToIP(ip), opt)
		}
		l <- logEntry{lv, m}
	}
}
