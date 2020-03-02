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
}

type sign struct {
	resetSched  chan bool
	stopSched   chan bool
	stopReceive chan bool
	getAdj      chan bool
}

func main() {
	log.Println("Starting main...")
	sys := &system{}
	var err error

	sys.signal = signalProcess(sys)

	if sys.config, err = readConfig(); err != nil {
		log.Fatal(err)
	}

	if sys.socket, err = socketOpen(sys.config); err != nil {
		log.Fatal(err)
	}

	a := initTable(sys)

	sys.socket.joinMcast()

	defer clearLocalTable()
	defer sys.socket.close()
	defer log.Println("Closing main...")

Loop:
	for {
		select {
		case <-sys.signal.stopReceive:
			break Loop
		default:
			b := make([]byte, 514) //Maximum size of RIP pdu - 504byte
			s, cm, _, err := sys.socket.connect.ReadFrom(b)
			if err != nil {
				log.Fatal(err)
			}
			ifc, err := net.InterfaceByIndex(cm.IfIndex)

			go func() {
				packet, err := readPacket(b[:s], ifc.Name, cm.Src)
				if err != nil {
					//Drop weird sourced packet
					return
				}

				pdu := packet.parse()
				err = pdu.validate(sys.config, packet.content)
				if err != nil {
					log.Println(err)
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
