package sockaddr_test

import (
	"net"
	"testing"

	sockaddr "github.com/saletnik/go-sockaddr2"
	sockaddrnet "github.com/saletnik/go-sockaddr2/net"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func ResolveAddr(network, address string) (net.Addr, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return net.ResolveTCPAddr(network, address)
	case "udp", "udp4", "udp6":
		return net.ResolveUDPAddr(network, address)
	case "ip", "ip4", "ip6":
		return net.ResolveIPAddr(network, address)
	case "unix", "unixgram", "unixpacket":
		return net.ResolveUnixAddr(network, address)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func Test_RawSockaddrAny_Length(t *testing.T) {
	t.Run("tcp network", func(t *testing.T) {
		addr, err := ResolveAddr("tcp", "127.0.0.1:80")
		assert.NoError(t, err)

		sa, salen, err := sockaddr.SockaddrToAny(sockaddrnet.NetAddrToSockaddr(addr))
		assert.NotNil(t, sa)
		assert.Equal(t, unix.SizeofSockaddrInet4, int(salen))
		assert.NoError(t, err)
	})

	t.Run("tcp6 network", func(t *testing.T) {
		addr, err := ResolveAddr("tcp", "[::1]:80")
		assert.NoError(t, err)

		sa, salen, err := sockaddr.SockaddrToAny(sockaddrnet.NetAddrToSockaddr(addr))
		assert.NotNil(t, sa)
		assert.Equal(t, unix.SizeofSockaddrInet6, int(salen))
		assert.NoError(t, err)
	})

	t.Run("udp network", func(t *testing.T) {
		addr, err := ResolveAddr("udp", "127.0.0.1:80")
		assert.NoError(t, err)

		sa, salen, err := sockaddr.SockaddrToAny(sockaddrnet.NetAddrToSockaddr(addr))
		assert.NotNil(t, sa)
		assert.Equal(t, unix.SizeofSockaddrInet4, int(salen))
		assert.NoError(t, err)
	})

	t.Run("udp6 network", func(t *testing.T) {
		addr, err := ResolveAddr("udp", "[::1]:80")
		assert.NoError(t, err)

		sa, salen, err := sockaddr.SockaddrToAny(sockaddrnet.NetAddrToSockaddr(addr))
		assert.NotNil(t, sa)
		assert.Equal(t, unix.SizeofSockaddrInet6, int(salen))
		assert.NoError(t, err)
	})

	t.Run("ip network", func(t *testing.T) {
		addr, err := ResolveAddr("ip", "127.0.0.1")
		assert.NoError(t, err)

		sa, salen, err := sockaddr.SockaddrToAny(sockaddrnet.NetAddrToSockaddr(addr))
		assert.NotNil(t, sa)
		assert.Equal(t, unix.SizeofSockaddrInet4, int(salen))
		assert.NoError(t, err)
	})

	t.Run("ip6 network", func(t *testing.T) {
		addr, err := ResolveAddr("ip", "::1")
		assert.NoError(t, err)

		sa, salen, err := sockaddr.SockaddrToAny(sockaddrnet.NetAddrToSockaddr(addr))
		assert.NotNil(t, sa)
		assert.Equal(t, unix.SizeofSockaddrInet6, int(salen))
		assert.NoError(t, err)
	})

	t.Run("unix network", func(t *testing.T) {
		addr, err := ResolveAddr("unix", "test.sock")
		assert.NoError(t, err)

		sa, salen, err := sockaddr.SockaddrToAny(sockaddrnet.NetAddrToSockaddr(addr))
		assert.NotNil(t, sa)
		assert.Equal(t, len("test.sock") + 3, int(salen))
		assert.NoError(t, err)
	})
}
