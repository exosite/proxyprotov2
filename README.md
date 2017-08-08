# proxyprotov2

Support for the haproxy proxy protocol version 2 for Go.  Careful!  It supports some Exosite-specific extensions to the protocol that conflict with haproxy 1.8 and later!

## How does it work?

Note: `*ProxyConn` implements `net.Conn`, and if you call `Close()` on it, it will close its underlying connection.  So, don't touch the underlying connection after creating a `ProxyConn`.

### On the receiving end

```golang
func echo(conn net.Conn) {
	pconn, err := proxyprotov2.NewProxyConnIncoming(conn)
	if err != nil {
		return
	}
	proxyInfo := pconn.Info()
	if proxyInfo != nil {
		log.Printf("SNI is %s", proxyInfo.SNI())
	}
	b := make([]byte, 1024)
	bytesRead, err := pconn.Read(b)
	if err != nil {
		return
	}
	_, err := pconn.Write(b[0:bytesRead])
	if err != nil {
		return
	}
}
```

### On the sending end
```golang
func sendIt(conn net.Conn) {
	tls := proxyprotov2.NewTlsTLV(proxyprotov2.PP2_CLIENT_SSL, 0)
	tls.SetSNI("example.com")
	// Deciding what srcIp, srcPort, dstIp, and dstPort should be is left
	// as an exercise for the reader.
	info := proxyprotov2.NewProxyInfo(false, proxyprotov2.ADDR_FAMILY_INET4, proxyprotov2.TRANSPORT_STREAM, srcIp, srcPort, dstIp, dstPort)
	pconn, err := proxyprotov2.NewProxyConnOutgoing(conn, info)
	if err != nil {
		return
	}
	_, err := pconn.Write([]byte("Hello, world!"))
	if err != nil {
		return
	}
	b := make([]byte, 1024)
	_, err := pconn.Read(b)
	if err != nil {
		return
	}
	log.Println(string(b))
}
```

## License

License is LGPLv3.
