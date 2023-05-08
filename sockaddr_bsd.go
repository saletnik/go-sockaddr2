//go:build darwin || dragonfly || freebsd || netbsd || openbsd
// +build darwin dragonfly freebsd netbsd openbsd

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
		raw4.Len = unix.SizeofSockaddrInet4
		raw4.Family = unix.AF_INET
		p := (*[2]byte)(unsafe.Pointer(&raw4.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		for i := 0; i < len(sa.Addr); i++ {
			raw4.Addr[i] = sa.Addr[i]
		}
		return raw, Socklen(raw4.Len), nil

	case *unix.SockaddrInet6:
		if sa.Port < 0 || sa.Port > 0xFFFF {
			return nil, 0, syscall.EINVAL
		}
		raw := new(unix.RawSockaddrAny)
		raw6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(raw))
		raw6.Len = unix.SizeofSockaddrInet6
		raw6.Family = unix.AF_INET6
		p := (*[2]byte)(unsafe.Pointer(&raw6.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		raw6.Scope_id = sa.ZoneId
		for i := 0; i < len(sa.Addr); i++ {
			raw6.Addr[i] = sa.Addr[i]
		}
		return raw, Socklen(raw6.Len), nil

	case *unix.SockaddrUnix:
		name := sa.Name
		n := len(name)
		raw := new(unix.RawSockaddrAny)
		rawx := (*unix.RawSockaddrUnix)(unsafe.Pointer(raw))
		if n >= len(rawx.Path) || n == 0 {
			return nil, 0, syscall.EINVAL
		}
		rawx.Len = byte(3 + n) // 2 for Family, Len; 1 for NUL
		rawx.Family = unix.AF_UNIX
		for i := 0; i < n; i++ {
			rawx.Path[i] = int8(name[i])
		}
		return raw, Socklen(rawx.Len), nil

	case *unix.SockaddrDatalink:
		if sa.Index == 0 {
			return nil, 0, syscall.EINVAL
		}
		raw := new(unix.RawSockaddrAny)
		rawl := (*unix.RawSockaddrDatalink)(unsafe.Pointer(raw))
		rawl.Len = sa.Len
		rawl.Family = unix.AF_LINK
		rawl.Index = sa.Index
		rawl.Type = sa.Type
		rawl.Nlen = sa.Nlen
		rawl.Alen = sa.Alen
		rawl.Slen = sa.Slen
		for i := 0; i < len(rawl.Data); i++ {
			rawl.Data[i] = sa.Data[i]
		}
		return raw, unix.SizeofSockaddrDatalink, nil
	}
	return nil, 0, syscall.EAFNOSUPPORT
}

func anyToSockaddr(rsa *unix.RawSockaddrAny) (unix.Sockaddr, error) {
	if rsa == nil {
		return nil, syscall.EINVAL
	}

	switch rsa.Addr.Family {
	case unix.AF_LINK:
		pp := (*unix.RawSockaddrDatalink)(unsafe.Pointer(rsa))
		sa := new(unix.SockaddrDatalink)
		sa.Len = pp.Len
		sa.Family = pp.Family
		sa.Index = pp.Index
		sa.Type = pp.Type
		sa.Nlen = pp.Nlen
		sa.Alen = pp.Alen
		sa.Slen = pp.Slen
		for i := 0; i < len(sa.Data); i++ {
			sa.Data[i] = pp.Data[i]
		}
		return sa, nil

	case unix.AF_UNIX:
		pp := (*unix.RawSockaddrUnix)(unsafe.Pointer(rsa))
		if pp.Len < 3 || pp.Len > unix.SizeofSockaddrUnix {
			return nil, syscall.EINVAL
		}
		sa := new(unix.SockaddrUnix)
		n := int(pp.Len) - 3 // subtract leading Family, Len, terminating NUL
		for i := 0; i < n; i++ {
			if pp.Path[i] == 0 {
				// found early NUL; assume Len is overestimating
				n = i
				break
			}
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
