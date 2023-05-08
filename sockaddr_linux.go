package sockaddr

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func sockaddrToAny(sa unix.Sockaddr) (*unix.RawSockaddrAny, Socklen, error) {
	if sa == nil {
		return nil, 0, syscall.EINVAL
	}

	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		if sa.Port < 0 || sa.Port > 0xFFFF {
			return nil, 0, syscall.EINVAL
		}
		raw := new(unix.RawSockaddrAny)
		raw4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(raw))
		raw4.Family = unix.AF_INET
		p := (*[2]byte)(unsafe.Pointer(&raw4.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		for i := 0; i < len(sa.Addr); i++ {
			raw4.Addr[i] = sa.Addr[i]
		}
		return raw, unix.SizeofSockaddrInet4, nil

	case *unix.SockaddrInet6:
		if sa.Port < 0 || sa.Port > 0xFFFF {
			return nil, 0, syscall.EINVAL
		}
		raw := new(unix.RawSockaddrAny)
		raw6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(raw))
		raw6.Family = unix.AF_INET6
		p := (*[2]byte)(unsafe.Pointer(&raw6.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		raw6.Scope_id = sa.ZoneId
		for i := 0; i < len(sa.Addr); i++ {
			raw6.Addr[i] = sa.Addr[i]
		}
		return raw, unix.SizeofSockaddrInet6, nil

	case *unix.SockaddrUnix:
		name := sa.Name
		n := len(name)
		raw := new(unix.RawSockaddrAny)
		rawx := (*unix.RawSockaddrUnix)(unsafe.Pointer(raw))
		if n >= len(rawx.Path) {
			return nil, 0, syscall.EINVAL
		}
		rawx.Family = unix.AF_UNIX
		for i := 0; i < n; i++ {
			rawx.Path[i] = int8(name[i])
		}
		// length is family (uint16), name, NUL.
		sl := Socklen(2)
		if n > 0 {
			sl += Socklen(n) + 1
		}
		if rawx.Path[0] == '@' {
			rawx.Path[0] = 0
			// Don't count trailing NUL for abstract address.
			sl--
		}
		return raw, sl, nil

	case *unix.SockaddrLinklayer:
		if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
			return nil, 0, syscall.EINVAL
		}
		raw := new(unix.RawSockaddrAny)
		rawl := (*unix.RawSockaddrLinklayer)(unsafe.Pointer(raw))
		rawl.Family = unix.AF_PACKET
		rawl.Protocol = sa.Protocol
		rawl.Ifindex = int32(sa.Ifindex)
		rawl.Hatype = sa.Hatype
		rawl.Pkttype = sa.Pkttype
		rawl.Halen = sa.Halen
		for i := 0; i < len(sa.Addr); i++ {
			rawl.Addr[i] = sa.Addr[i]
		}
		return raw, unix.SizeofSockaddrLinklayer, nil
	}
	return nil, 0, syscall.EAFNOSUPPORT
}

func anyToSockaddr(rsa *unix.RawSockaddrAny) (unix.Sockaddr, error) {
	if rsa == nil {
		return nil, syscall.EINVAL
	}

	switch rsa.Addr.Family {
	case unix.AF_NETLINK:
		pp := (*unix.RawSockaddrNetlink)(unsafe.Pointer(rsa))
		sa := new(unix.SockaddrNetlink)
		sa.Family = pp.Family
		sa.Pad = pp.Pad
		sa.Pid = pp.Pid
		sa.Groups = pp.Groups
		return sa, nil

	case unix.AF_PACKET:
		pp := (*unix.RawSockaddrLinklayer)(unsafe.Pointer(rsa))
		sa := new(unix.SockaddrLinklayer)
		sa.Protocol = pp.Protocol
		sa.Ifindex = int(pp.Ifindex)
		sa.Hatype = pp.Hatype
		sa.Pkttype = pp.Pkttype
		sa.Halen = pp.Halen
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case unix.AF_UNIX:
		pp := (*unix.RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(unix.SockaddrUnix)
		if pp.Path[0] == 0 {
			// "Abstract" Unix domain socket.
			// Rewrite leading NUL as @ for textual display.
			// (This is the standard convention.)
			// Not friendly to overwrite in place,
			// but the callers below don't care.
			pp.Path[0] = '@'
		}

		// Assume path ends at NUL.
		// This is not technically the Linux semantics for
		// abstract Unix domain sockets--they are supposed
		// to be uninterpreted fixed-size binary blobs--but
		// everyone uses this convention.
		n := 0
		for n < len(pp.Path) && pp.Path[n] != 0 {
			n++
		}
		bytes := (*[10000]byte)(unsafe.Pointer(&pp.Path[0]))[0:n]
		sa.Name = string(bytes)
		return sa, nil

	case unix.AF_INET:
		pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(unix.SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case unix.AF_INET6:
		pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(unix.SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil
	}
	return nil, syscall.EAFNOSUPPORT
}
