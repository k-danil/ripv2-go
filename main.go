package main

import (
	"encoding/binary"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type system struct {
	config  *config
	socket  *socket
	local   *local
	signal  *sign
	logger  logger
	cfgPath string
}

type sign struct {
	resetAdj    chan struct{}
	resetNbr    chan struct{}
	stopSched   chan struct{}
	stopReceive chan struct{}
	getAdj      chan struct{}
	getNbr      chan struct{}
}

var sys = system{}

func init() {
	const (
		defaultCfgPath = "settings.toml"
	)
	flag.StringVar(&sys.cfgPath, "f", defaultCfgPath, "config file")
	flag.Parse()

	sys.logger = logProcess()
	sys.signal = signalProcess()
}

func main() {
	// defer profile.Start(profile.MemProfile).Stop()
	var err error

	sys.logger.send(info, "starting main")

	clrRoutes()

	if sys.config, err = readConfig(); err != nil {
		sys.logger.send(fatal, err)
	}

	if sys.socket, err = socketOpen(); err != nil {
		sys.logger.send(fatal, err)
	}

	adj := initAdjTable()
	nbr := initNbrTable()

	// go tableSubscr()

	if err = sys.socket.joinMcast(); err != nil {
		sys.logger.send(erro, err)
	}

	defer clrRoutes()
	defer sys.socket.close()
	defer sys.logger.send(info, "closing main")

Loop:
	for {
		select {
		case <-sys.signal.stopReceive:
			break Loop
		default:
			b := make([]byte, (sys.config.Global.EntryCount*entrySize + headerSize))

			s, cm, _, err := sys.socket.connect.ReadFrom(b)
			if err, ok := err.(net.Error); ok && !err.Timeout() {
				sys.logger.send(fatal, err)
			} else if err, ok := err.(net.Error); ok && err.Timeout() {
				break
			}

			go func() {
				src := binary.BigEndian.Uint32(cm.Src)
				packet, err := readPacket(b[:s], cm.IfIndex, src)
				if err != nil {
					//Drop weird sourced packet
					return
				}

				pdu := packet.parse()
				if sys.config.Global.Log == debug {
					sys.logger.send(debug, pdu)
				}

				if _, ok := sys.config.Neighbors[src]; ok {
					err = pdu.validate(sys.config.Neighbors[src].KeyChain)
				} else if _, ok := sys.config.Interfaces[cm.IfIndex]; ok {
					err = pdu.validate(sys.config.Interfaces[cm.IfIndex].KeyChain)
				}

				if err != nil {
					sys.logger.send(warn, err)
				} else {
					nbr.update(pdu.serviceFields.ip, pdu.serviceFields.ifi)
					adj.procIncom(pdu)
				}
			}()
		}
	}
}

func signalProcess() *sign {
	signChan := make(chan os.Signal)
	signal.Notify(signChan)

	sign := &sign{}
	sign.getAdj = make(chan struct{})
	sign.getNbr = make(chan struct{})
	sign.resetAdj = make(chan struct{})
	sign.resetNbr = make(chan struct{})
	sign.stopReceive = make(chan struct{})
	sign.stopSched = make(chan struct{})

	go func() {
		for s := range signChan {
			switch s {
			case syscall.SIGHUP:
				if config, err := readConfig(); err != nil {
					sys.logger.send(erro, err)
				} else {
					sys.config = config
				}
				if err := sys.socket.leaveMcast(); err != nil {
					sys.logger.send(erro, err)
				}
				if err := sys.socket.joinMcast(); err != nil {
					sys.logger.send(erro, err)
				}
				sign.resetAdj <- struct{}{}
			case os.Interrupt:
				sign.stopSched <- struct{}{}
				sign.stopReceive <- struct{}{}
				sys.socket.timeout(1)
				return
			case syscall.SIGUSR1:
				sign.getAdj <- struct{}{}
			case syscall.SIGUSR2:
				sign.getNbr <- struct{}{}
			}
		}
	}()

	return sign
}
