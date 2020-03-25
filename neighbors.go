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

	if n.flags&static != 0 {
		m += "static "
	}
	if n.flags&auth != 0 {
		m += "auth "
	}

	return fmt.Sprintf("uptime: %v | %s", ctime-n.timestamp, m)
}

func initNbrTable() *nbrTable {
	n := &nbrTable{}
	n.entry = make(map[uint32]*nbr)
	n.addStatic()
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
		case <-sys.signal.resetNbr:
			n.clearAll()
			n.addStatic()
		}
	}
}

func (n *nbrTable) update(ip uint32, ifi int) {
	n.mux.Lock()
	defer n.mux.Unlock()
	ctime := time.Now().Unix()
	if n.entry[ip] == nil {
		n.entry[ip] = &nbr{
			flags:     state,
			timestamp: ctime,
		}
	} else {
		n.entry[ip].flags |= state
		n.entry[ip].timestamp = ctime
	}

	if n.entry[ip].flags&static != 0 {
		return
	}

	if sys.config.Interfaces[ifi].KeyChain.AuthType != 0 {
		n.entry[ip].flags |= auth
	} else {
		n.entry[ip].flags &^= auth
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
				n.entry[ip].flags &^= state
			}
		case n.entry[ip].flags&static != 0:
			continue
		case n.entry[ip].flags&state == 0:
			if (ctime - opt.timestamp) > 3600 {
				delete(n.entry, ip)
			}
		}
	}
}

func (n *nbrTable) clearAll() {
	n.mux.Lock()
	defer n.mux.Unlock()
	for ip := range n.entry {
		delete(n.entry, ip)
	}
}

func (n *nbrTable) addStatic() {
	n.mux.Lock()
	defer n.mux.Unlock()
	for ip, opt := range sys.config.Neighbors {
		if n.entry[ip] == nil {
			n.entry[ip] = &nbr{
				flags: static,
			}
		} else {
			n.entry[ip].flags |= static
		}

		if opt.KeyChain.AuthType != 0 {
			n.entry[ip].flags |= auth
		}
	}
}
