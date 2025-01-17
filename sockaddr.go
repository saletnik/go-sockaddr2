// Deprecated: This package is not maintained any longer.
package sockaddr

import (
	sockaddrnet "github.com/saletnik/go-sockaddr2/net"
)

// Socklen is a type for the length of a sockaddr.
type Socklen uint

// SockaddrToAny converts a Sockaddr into a RawSockaddrAny
// The implementation is platform dependent.
func SockaddrToAny(sa sockaddrnet.Sockaddr) (*sockaddrnet.RawSockaddrAny, Socklen, error) {
	return sockaddrToAny(sa)
}

// SockaddrToAny converts a RawSockaddrAny into a Sockaddr
// The implementation is platform dependent.
func AnyToSockaddr(rsa *sockaddrnet.RawSockaddrAny) (sockaddrnet.Sockaddr, error) {
	return anyToSockaddr(rsa)
}
