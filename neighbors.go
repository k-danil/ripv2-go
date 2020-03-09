package main

import (
	"fmt"
	"sync"
	"time"
)

type nbrTable struct {
	entry map[uint32]*nbr
	mux   sync.Mutex
}

const (
	state uint8 = 1 << iota
	static
	auth
)

type nbr struct {
	flags     uint8
	timestamp int64
}

func (n *nbr) String() string {
	ctime := time.Now().Unix()
	m := ""
	if n.flags&state != 0 {
		m += "up "
	} else {
		m += "down "
	}
	switch {
	case n.flags&static != 0:
		m += "static "
	case n.flags&auth != 0:
		m += "auth "
	}

	return fmt.Sprintf("uptime: %v | %v", ctime-n.timestamp, m)
}

func initNbrTable() *nbrTable {
	n := &nbrTable{}
	n.entry = make(map[uint32]*nbr)
	go n.scheduler()

	return n
}

func (n *nbrTable) scheduler() {
	tWorker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-tWorker.C:
			n.clear()
		case <-sys.signal.getNbr:
			sys.logger.send(user, n.entry)
		}
	}
}

func (n *nbrTable) update(ip uint32, flags uint8) {
	n.mux.Lock()
	defer n.mux.Unlock()
	ctime := time.Now().Unix()
	if n.entry[ip] == nil {
		n.entry[ip] = &nbr{
			flags:     flags,
			timestamp: ctime,
		}
	} else {
		n.entry[ip].flags = flags
		n.entry[ip].timestamp = ctime
	}
}

func (n *nbrTable) clear() {
	n.mux.Lock()
	defer n.mux.Unlock()
	ctime := time.Now().Unix()
	for ip, opt := range n.entry {
		switch {
		case n.entry[ip].flags&state != 0:
			if (ctime - opt.timestamp) > 600 {
				n.entry[ip].flags = n.entry[ip].flags &^ state
			}
		case n.entry[ip].flags&state == 0:
			if (ctime - opt.timestamp) > 3600 {
				delete(n.entry, ip)
			}
		}
	}
}
