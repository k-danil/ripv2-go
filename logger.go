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
	logChan := make(chan logEntry, 10)

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
				cLevel = sys.config.Local.Log
			} else {
				cLevel = 5
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
		if lv == 1 {
			time.Sleep(100 * time.Millisecond)
			os.Exit(1)
		}
	case string:
		l <- logEntry{lv, msg.(string)}
	case *pdu:
		m := fmt.Sprintf("%+v\n", msg)
		l <- logEntry{lv, m}
	case map[uint64]*adj:
		m := "Adjustments:\n"
		for _, v := range msg.(map[uint64]*adj) {
			m += fmt.Sprintf("%v\n", v.String())
		}
		l <- logEntry{lv, m}
	case map[uint32]*nbr:
		m := "Neighbors:\n"
		for ip, v := range msg.(map[uint32]*nbr) {
			m += fmt.Sprintf("ip: %v\t%v\n", uintToIP(ip), v.String())
		}
		l <- logEntry{lv, m}
	}
}
