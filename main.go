package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type system struct {
	config *config
	socket *socket
	signal *sign
	logger logger
	debug  bool
}

type sign struct {
	resetSched  chan bool
	stopSched   chan bool
	stopReceive chan bool
	getAdj      chan bool
}

func init() {

}

func main() {
	sys := &system{}
	var err error

	sys.logger = logProcess(sys)
	sys.signal = signalProcess(sys)

	sys.logger.send(info, "starting main")

	if sys.config, err = readConfig(); err != nil {
		sys.logger.send(fatal, err)
	}
	if sys.config.Local.Log == 5 {
		sys.debug = true
	}

	if sys.socket, err = socketOpen(sys.config); err != nil {
		sys.logger.send(fatal, err)
	}

	a := initTable(sys)

	if err = sys.socket.joinMcast(); err != nil {
		sys.logger.send(erro, err)
	}

	defer clearLocalTable()
	defer sys.socket.close()
	defer sys.logger.send(info, "closing main")

Loop:
	for {
		select {
		case <-sys.signal.stopReceive:
			break Loop
		default:
			b := make([]byte, 514) //Maximum size of RIP pdu - 504byte
			s, cm, _, err := sys.socket.connect.ReadFrom(b)
			if err != nil {
				sys.logger.send(fatal, err)
			}
			ifc, err := net.InterfaceByIndex(cm.IfIndex)
			if err != nil {
				sys.logger.send(erro, err)
			}

			go func() {
				packet, err := readPacket(b[:s], ifc.Name, cm.Src)
				if err != nil {
					//Drop weird sourced packet
					return
				}

				pdu := packet.parse()
				if sys.debug {
					sys.logger.send(debug, pdu)
				}
				err = pdu.validate(sys.config, packet.content)
				if err != nil {
					sys.logger.send(warn, err)
				} else {
					a.adjProcess(pdu)
				}
			}()
		}
	}
}

func signalProcess(sys *system) *sign {
	var err error
	signChan := make(chan os.Signal)
	signal.Notify(signChan)

	sign := &sign{}
	sign.getAdj = make(chan bool)
	sign.resetSched = make(chan bool)
	sign.stopReceive = make(chan bool)
	sign.stopSched = make(chan bool)

	go func() {
		for s := range signChan {
			switch s {
			case syscall.SIGHUP:
				if sys.config, err = readConfig(); err != nil {
					log.Fatal(err)
				}
				if sys.socket.leaveMcast() != nil {
					log.Println()
				}
				if sys.socket.joinMcast() != nil {
					log.Println()
				}
				sign.resetSched <- true
			case os.Interrupt:
				sign.stopSched <- true
				sign.stopReceive <- true
				return
			case syscall.SIGUSR1:
				sign.getAdj <- true
			}
		}
	}()

	return sign
}
