package main

import (
	"errors"
	"net"
	"syscall"
)

const (
	SO_ORIGINAL_DST = 80
)

func GetOriginalDestination(conn net.Conn) ([]byte, error) {
	sysrawconn, f := conn.(syscall.Conn)
	if !f {
		return nil, errors.New("unable to get syscall.Conn")
	}

	rawConn, err := sysrawconn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var rawaddr []byte
	err = rawConn.Control(func(fd uintptr) {
		addr, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err != nil {
			return
		}

		//idType ipv4 port = 1 + 4 + 2
		rawaddr = make([]byte, 7)

		rawaddr[0] = 1 // typeIPv4, type is ipv4 address
		copy(rawaddr[1:5], addr.Multiaddr[4:8])
		copy(rawaddr[5:7], addr.Multiaddr[2:4])
	})

	if err != nil {
		return nil, err
	}

	return rawaddr, nil
}
