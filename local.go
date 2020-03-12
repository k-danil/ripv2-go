package main

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

type local struct {
	mux sync.Mutex
}

func getTable(ifi int) (*pdu, error) {
	link, err := netlink.LinkByIndex(ifi)
	if err != nil {
		return nil, err
	}

	iplist, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	pdu := &pdu{
		header: header{Version: 2, Command: 2},
		serviceFields: serviceFields{
			ip:        binary.BigEndian.Uint32([]byte{127, 0, 0, 1}),
			ifi:       link.Attrs().Index,
			timestamp: time.Now().Unix(),
		},
	}
	for _, ipAddr := range iplist {
		if ipAddr.IP.IsLoopback() {
			continue
		}
		pdu.routeEntries = append(pdu.routeEntries, routeEntry{
			AFI:     afiIPv4,
			Network: binary.BigEndian.Uint32(ipAddr.IP.Mask(ipAddr.Mask)),
			Mask:    binary.BigEndian.Uint32(ipAddr.Mask),
		})
	}
	return pdu, nil
}

func addRoute(netid ipNet, nextHop uint32) error {
	if uintToIP(nextHop).IsLoopback() {
		return nil
	}

	dst := &net.IPNet{
		IP:   uintToIP(netid.ip),
		Mask: net.IPMask(uintToIP(netid.mask)),
	}
	route := netlink.Route{
		Dst:      dst,
		Protocol: 10,
		Priority: sys.config.Global.Metric,
		Gw:       uintToIP(nextHop),
	}
	if err := netlink.RouteAdd(&route); err != nil {
		return err
	}
	return nil
}

func replRoute(netid ipNet, nextHop uint32) error {
	if uintToIP(nextHop).IsLoopback() {
		return nil
	}

	dst := &net.IPNet{
		IP:   uintToIP(netid.ip),
		Mask: net.IPMask(uintToIP(netid.mask)),
	}
	route := netlink.Route{
		Dst:      dst,
		Protocol: 10,
		Priority: sys.config.Global.Metric,
		Gw:       uintToIP(nextHop),
	}
	if err := netlink.RouteReplace(&route); err != nil {
		return err
	}
	return nil
}

func remRoute(netid ipNet) error {
	dst := &net.IPNet{
		IP:   uintToIP(netid.ip),
		Mask: net.IPMask(uintToIP(netid.ip)),
	}
	route := netlink.Route{
		Dst:      dst,
		Protocol: 10,
	}

	if err := netlink.RouteDel(&route); err != nil {
		return err
	}
	return nil
}

func clrRoutes() error {
	filter := &netlink.Route{
		Protocol: 10,
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}

	for _, route := range routes {
		if err := netlink.RouteDel(&route); err != nil {
			return err
		}
	}
	return nil
}

func isLocal(addr uint32) (bool, error) {
	iplist, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return false, err
	}

	for _, ip := range iplist {
		if ip.IP.Equal(uintToIP(addr)) {
			return true, nil
		}
	}

	return false, nil
}
