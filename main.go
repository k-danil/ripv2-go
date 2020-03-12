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
	resetSched  chan bool
	stopSched   chan bool
	stopReceive chan bool
	getAdj      chan bool
	getNbr      chan bool
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
	err = sys.config.validate()
	if err != nil {
		sys.logger.send(warn, err)
	}

	if sys.socket, err = socketOpen(); err != nil {
		sys.logger.send(fatal, err)
	}

	adj := initAdjTable()
	nbr := initNbrTable()

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
			b := make([]byte, (sys.config.Global.MsgSize*20 + 4))

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
				if sys.config.Global.Log == 5 {
					sys.logger.send(debug, pdu)
				}

				if !cm.Dst.IsMulticast() {
					err = pdu.validate(packet.content, sys.config.Neighbors[src].KeyChain)
				} else {
					err = pdu.validate(packet.content, sys.config.Interfaces[cm.IfIndex].KeyChain)
				}

				if err != nil {
					sys.logger.send(warn, err)
				} else {
					if pdu.serviceFields.authType != 0 {
						nbr.update(pdu.serviceFields.ip, state|auth)
					} else {
						nbr.update(pdu.serviceFields.ip, state)
					}
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
	sign.getAdj = make(chan bool)
	sign.getNbr = make(chan bool)
	sign.resetSched = make(chan bool)
	sign.stopReceive = make(chan bool)
	sign.stopSched = make(chan bool)

	go func() {
		for s := range signChan {
			switch s {
			case syscall.SIGHUP:
				if config, err := readConfig(); err != nil {
					sys.logger.send(erro, err)
				} else {
					sys.config = config
				}
				err := sys.config.validate()
				if err != nil {
					sys.logger.send(warn, err)
				}
				if err := sys.socket.leaveMcast(); err != nil {
					sys.logger.send(erro, err)
				}
				if err := sys.socket.joinMcast(); err != nil {
					sys.logger.send(erro, err)
				}
				sign.resetSched <- true
			case os.Interrupt:
				sign.stopSched <- true
				sign.stopReceive <- true
				sys.socket.timeout(1)
				return
			case syscall.SIGUSR1:
				sign.getAdj <- true
			case syscall.SIGUSR2:
				sign.getNbr <- true
			}
		}
	}()

	return sign
}
