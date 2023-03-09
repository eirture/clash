package vmess

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type quicConn struct {
	stream quic.Stream
	local  net.Addr
	remote net.Addr
}

func (qc *quicConn) LocalAddr() net.Addr {
	return qc.local
}

func (qc *quicConn) RemoteAddr() net.Addr {
	return qc.remote
}

func (qc *quicConn) SetDeadline(t time.Time) error {
	return qc.stream.SetDeadline(t)
}

func (qc *quicConn) SetReadDeadline(t time.Time) error {
	return qc.stream.SetReadDeadline(t)
}

func (qc *quicConn) SetWriteDeadline(t time.Time) error {
	return qc.stream.SetWriteDeadline(t)
}

func (qc *quicConn) Read(b []byte) (int, error) {
	return qc.stream.Read(b)
}

func (qc *quicConn) Write(b []byte) (int, error) {
	return qc.stream.Write(b)
}

func (qc *quicConn) Close() (err error) {
	return qc.stream.Close()
}

func StreamQuicConn(stream quic.Stream, local, remote net.Addr) (net.Conn, error) {
	return &quicConn{
		stream: stream,
		local:  local,
		remote: remote,
	}, nil
}

type QuicTransport struct {
	conns map[string]quic.Connection
	mux   sync.Mutex

	TLSConfig      *tls.Config
	DialTLSContext func(ctx context.Context, addr string, config *tls.Config) (quic.Connection, error)
}

func NewQuicTransport(tlsConfig *tls.Config, quicConfig *quic.Config) *QuicTransport {
	dialFn := func(ctx context.Context, addr string, config *tls.Config) (quic.Connection, error) {
		return quic.DialAddrContext(ctx, addr, config, quicConfig)
	}
	return &QuicTransport{
		conns:          make(map[string]quic.Connection),
		TLSConfig:      tlsConfig,
		DialTLSContext: dialFn,
	}
}

func (tr *QuicTransport) OpenStream(addr string) (stream quic.Stream, conn quic.Connection, err error) {
	conn, isReused, err := tr.getConn(addr)
	if err != nil {
		return nil, nil, err
	}
	stream, err = conn.OpenStream()
	if err != nil {
		tr.removeConn(addr)
		if isReused {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return tr.OpenStream(addr)
			}
		}
		return
	}
	return
}

func (tr *QuicTransport) getConn(addr string) (conn quic.Connection, isReused bool, err error) {
	tr.mux.Lock()
	defer tr.mux.Unlock()

	conn, ok := tr.conns[addr]
	if !ok {
		conn, err = tr.DialTLSContext(context.Background(), addr, tr.TLSConfig)
		if err != nil {
			return
		}
		tr.conns[addr] = conn
	} else {
		isReused = conn.ConnectionState().TLS.HandshakeComplete
	}
	return
}

func (tr *QuicTransport) removeConn(addr string) {
	tr.mux.Lock()
	defer tr.mux.Unlock()

	if conn, ok := tr.conns[addr]; ok {
		conn.CloseWithError(0, "")
	}
	delete(tr.conns, addr)
}
