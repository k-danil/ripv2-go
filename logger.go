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

func logProcess(sys *system) chan<- logEntry {
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

func (l logger) send(lv uint8, mess interface{}) {
	switch mess.(type) {
	case error:
		l <- logEntry{lv, mess.(error).Error()}
		if lv == 1 {
			time.Sleep(100 * time.Millisecond)
			os.Exit(1)
		}
	case string:
		l <- logEntry{lv, mess.(string)}
	case *pdu:
		m := fmt.Sprintf("%+v\n", mess)
		l <- logEntry{lv, m}
	}
}
