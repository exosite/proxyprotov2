package proxyproto

import (
	"io"
	"net"
	"fmt"
	"time"
	"bufio"
	"bytes"
	"strings"
	"encoding/binary"
	"crypto/x509"
)

var (
	ProxyProtoV2Header = [...]byte{ 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A }
)

const (
	PP2_TYPE_ALPN byte = 0x01
	PP2_TYPE_AUTHORITY byte = 0x02
	PP2_TYPE_CRC32C byte = 0x03
	PP2_TYPE_NOOP byte = 0x04
	PP2_TYPE_SSL byte = 0x20
	// Exosite bastardization:
	PP2_TYPE_SSL_VERSION byte = 0x21
	PP2_TYPE_SSL_CN byte = 0x22
	PP2_TYPE_SSL_SNI byte = 0x23
	PP2_TYPE_SSL_CERT byte = 0x24
	PP2_TYPE_SSL_FP byte = 0x25
	// (This stuff is called PP2_SUBTYPE_SSL_* in the docs.  WTF?)
	/////////////////////////////
	PP2_TYPE_NETNS byte = 0x30

	PP2_CLIENT_SSL = 0x01
	PP2_CLIENT_CERT_CONN = 0x02
	PP2_CLIENT_CERT_SESS = 0x04
	PP2_CLIENT_SNI = 0x08

	ADDR_FAMILY_UNSPEC = 0x0
	ADDR_FAMILY_INET4 = 0x1
	ADDR_FAMILY_INET6 = 0x2
	ADDR_FAMILY_UNIX = 0x3

	TRANSPORT_UNSPEC = 0x0
	TRANSPORT_STREAM = 0x1
	TRANSPORT_DGRAM = 0x2
)

type ProxyInfo struct {
	IsLocal bool
	AddrFamily byte
	Transport byte
	AddrListBytes []byte
	TLVs []TLV
}

func makeAddrBlock(srcIp net.IP, srcPort uint16, dstIp net.IP, dstPort uint16) ([]byte, error) {
	srcIp4 := srcIp.To4()
	dstIp4 := dstIp.To4()
	if (srcIp4 != nil) != (dstIp4 != nil) {
		return nil, fmt.Errorf("Mixed IPv4 and IPv6 addresses")
	}
	var addrBytes []byte
	if srcIp4 != nil {
		buf := new(bytes.Buffer)
		buf.Write(srcIp4)
		buf.Write(dstIp4)
		binary.Write(buf, binary.BigEndian, srcPort)
		binary.Write(buf, binary.BigEndian, dstPort)
		addrBytes = buf.Bytes()
	} else {
		buf := new(bytes.Buffer)
		srcIp16 := srcIp.To16()
		dstIp16 := dstIp.To16()
		if srcIp16 == nil || dstIp16 == nil {
			return nil, fmt.Errorf("Invalid addresses")
		}
		buf.Write(srcIp16)
		buf.Write(dstIp16)
		binary.Write(buf, binary.BigEndian, srcPort)
		binary.Write(buf, binary.BigEndian, dstPort)
		addrBytes = buf.Bytes()
	}

	return addrBytes, nil
}

func NewProxyInfo(isLocal bool, addrFamily, transport byte, srcIp net.IP, srcPort uint16, dstIp net.IP, dstPort uint16) (*ProxyInfo, error) {
	addrBytes, err := makeAddrBlock(srcIp, srcPort, dstIp, dstPort)
	if err != nil {
		return nil, err
	}
	return &ProxyInfo{
		IsLocal: isLocal,
		AddrFamily: addrFamily,
		Transport: transport,
		AddrListBytes: addrBytes,
		TLVs: make([]TLV, 0),
	}, nil
}

func (self *ProxyInfo) AddTLV(tlv TLV) {
	self.TLVs = append(self.TLVs, tlv)
}

func (self *ProxyInfo) Addrs() ([]string, error) {
	addrListBytesLen := len(self.AddrListBytes)
	addrs := make([]string, 0)
	switch self.AddrFamily {
	case ADDR_FAMILY_UNSPEC:
		return addrs, nil
	case ADDR_FAMILY_INET4:
		if addrListBytesLen != 12 {
			return addrs, fmt.Errorf("Expected 12 bytes but got %d", addrListBytesLen)
		}

		var srcPort uint16
		err := binary.Read(bytes.NewReader(self.AddrListBytes[8:10]), binary.BigEndian, &srcPort)
		if err != nil {
			return addrs, err
		}
		srcAddr := net.IP(self.AddrListBytes[0:4])
		addrs = append(addrs, fmt.Sprintf("%s:%d", srcAddr, srcPort))

		var dstPort uint16
		err = binary.Read(bytes.NewReader(self.AddrListBytes[10:12]), binary.BigEndian, &dstPort)
		if err != nil {
			return addrs, err
		}
		dstAddr := net.IP(self.AddrListBytes[4:8])
		addrs = append(addrs, fmt.Sprintf("%s:%d", dstAddr, dstPort))
		return addrs, nil
	case ADDR_FAMILY_INET6:
		if addrListBytesLen != 36 {
			return addrs, fmt.Errorf("Expected 36 bytes but got %d", addrListBytesLen)
		}

		var srcPort uint16
		err := binary.Read(bytes.NewReader(self.AddrListBytes[8:10]), binary.BigEndian, &srcPort)
		if err != nil {
			return addrs, err
		}
		srcAddr := net.IP(self.AddrListBytes[0:16])
		addrs = append(addrs, fmt.Sprintf("%s:%d", srcAddr, srcPort))

		var dstPort uint16
		err = binary.Read(bytes.NewReader(self.AddrListBytes[10:12]), binary.BigEndian, &dstPort)
		if err != nil {
			return addrs, err
		}
		dstAddr := net.IP(self.AddrListBytes[16:32])
		addrs = append(addrs, fmt.Sprintf("%s:%d", dstAddr, dstPort))
		return addrs, nil
	case ADDR_FAMILY_UNIX:
		if addrListBytesLen !=216 {
			return addrs, fmt.Errorf("Expected 216 bytes but got %d", addrListBytesLen)
		}
		srcAddr := strings.TrimSpace(string(self.AddrListBytes[0:108]))
		dstAddr := strings.TrimSpace(string(self.AddrListBytes[108:216]))
		addrs = append(addrs, srcAddr)
		addrs = append(addrs, dstAddr)
		return addrs, nil
	default:
		return addrs, fmt.Errorf("Bad address family: %x", self.AddrFamily)
	}
}

func (self *ProxyInfo) WriteTo(w io.Writer) error {
	buf := bufio.NewWriter(w)
	_, err := buf.Write(ProxyProtoV2Header[:])
	if err != nil {
		return err
	}

	tlvsBytesLen := 0
	for _, tlv := range self.TLVs {
		tlvsBytesLen += 3 + int(tlv.Size())
	}

	if self.IsLocal {
		buf.WriteByte(0x20)
	} else {
		buf.WriteByte(0x21)
	}
	buf.WriteByte((self.AddrFamily << 4) | self.Transport)
	extLen := uint16(len(self.AddrListBytes) + tlvsBytesLen)
	err = binary.Write(buf, binary.BigEndian, extLen)
	// I cannot fathom how this call could possibly fail, but let's be safe...
	if err != nil {
		return err
	}

	_, err = buf.Write(self.AddrListBytes)
	if err != nil {
		return err
	}

	for _, tlv := range self.TLVs {
		err = tlv.WriteTo(buf)
		if err != nil {
			return err
		}
	}

	return buf.Flush()
}

type TLV interface {
	Type() byte
	Size() uint16
	WriteTo(w io.Writer) error
}

type GenericTLV struct {
	RecType byte
	Value []byte
}

func (self *GenericTLV) Type() byte {
	return self.RecType
}

func (self *GenericTLV) Size() uint16 {
	return uint16(len(self.Value))
}

func (self *GenericTLV) WriteTo(w io.Writer) error {
	prologue := new(bytes.Buffer)
	prologue.WriteByte(self.RecType)
	err := binary.Write(prologue, binary.BigEndian, uint16(len(self.Value)))
	// I cannot fathom how this call could possibly fail, but let's be safe...
	if err != nil {
		return err
	}
	_, err = prologue.WriteTo(w)
	if err != nil {
		return err
	}

	_, err = w.Write(self.Value)
	return err
}

func ParseTLV(headerBytes []byte) (TLV, []byte, error) {
	if headerBytes == nil || len(headerBytes) == 0 {
		return nil, headerBytes, io.EOF
	}
	tlvType := headerBytes[0]
	var tlvLen uint16
	err := binary.Read(bytes.NewReader(headerBytes[1:]), binary.BigEndian, &tlvLen)
	if err != nil {
		return nil, headerBytes, err
	}
	hb := headerBytes[3:]
	if uint(len(hb)) < uint(tlvLen) {
		return nil, headerBytes, fmt.Errorf("Expected %d bytes; got %d bytes", tlvLen, len(hb))
	}
	value := hb[0:tlvLen]
	var tlv TLV
	if tlvType == PP2_TYPE_SSL {
		var tlserr *TlsParseError
		tlv, tlserr = parseTls(value)
		if err != nil {
			return nil, headerBytes, tlserr
		}
	} else {
		tlv = &GenericTLV{
			RecType: tlvType,
			Value: value,
		}
	}
	return tlv, hb[tlvLen:], nil
}

type TlsParseError struct {
	errs []error
}

func (self *TlsParseError) Error() string {
	errStrs := make([]string, 0)
	for _, err := range self.errs {
		errStrs = append(errStrs, err.Error())
	}
	return strings.Join(errStrs, "\n")
}

func parseTls(value []byte) (*TlsTLV, *TlsParseError) {
	var tlsInfo TlsTLV
	errs := make([]error, 0)
	remainingBytes := value[:]

	tlsInfo.flags = remainingBytes[0]
	usingSNI := (tlsInfo.flags & PP2_CLIENT_SNI) != 0
	gotSNI := false
	remainingBytes = remainingBytes[1:]

	err := binary.Read(bytes.NewReader(remainingBytes), binary.BigEndian, &tlsInfo.verification)
	if err != nil {
		tlsInfo.verification = -1
	}
	remainingBytes = remainingBytes[4:]

	for {
		var rawtlv TLV
		var err error
		rawtlv, remainingBytes, err = ParseTLV(remainingBytes)
		if err != nil {
			if err == io.EOF {
				break
			}
			errs = append(errs, err)
			return nil, &TlsParseError{
				errs: errs,
			}
		}
		tlv, isGeneric := rawtlv.(*GenericTLV)
		if !isGeneric {
			// This should never happen.
			continue
		}
		switch tlv.RecType {
		case PP2_TYPE_SSL_VERSION:
			tlsInfo.version = tlv.Value
		case PP2_TYPE_SSL_CN:
			tlsInfo.cn = tlv.Value
		case PP2_TYPE_SSL_SNI:
			tlsInfo.sni = tlv.Value
			gotSNI = true
			if !usingSNI {
				errs = append(errs, fmt.Errorf("Didn't expect an SNI record, but got one anyway!"))
			}
		case PP2_TYPE_SSL_CERT:
			tlsInfo.certs = tlv.Value
		case PP2_TYPE_SSL_FP:
			tlsInfo.fp = tlv.Value
		default:
			errs = append(errs, fmt.Errorf("Unknown TLS TLV type 0x%x", tlv.Type))
		}
		if len(remainingBytes) == 0 {
			break
		}
	}

	if usingSNI && !gotSNI {
		errs = append(errs, fmt.Errorf("Expected an SNI record, but didn't get one!"))
	}

	if len(errs) > 0 {
		return &tlsInfo, &TlsParseError{
			errs: errs,
		}
	} else {
		return &tlsInfo, nil
	}
}

type TlsTLV struct {
	flags byte
	verification int32
	version []byte
	cn []byte
	sni []byte
	certs []byte
	fp []byte
}

func NewTlsTLV(flags byte, verification int32) *TlsTLV {
	return &TlsTLV{
		flags: flags,
		verification: verification,
		version: nil,
		cn: nil,
		sni: nil,
		certs: nil,
		fp: nil,
	}
}

func (self *TlsTLV) Type() byte {
	return PP2_TYPE_SSL
}

func (self *TlsTLV) Flags() byte {
	return self.flags
}

func (self *TlsTLV) Verification() int32 {
	return self.verification
}

func (self *TlsTLV) Version() string {
	return string(self.version)
}
func (self *TlsTLV) SetVersion(version string) {
	self.version = []byte(version)
}

func (self *TlsTLV) CN() string {
	return string(self.cn)
}
func (self *TlsTLV) SetCN(cn string) {
	self.cn = []byte(cn)
}

func (self *TlsTLV) SNI() string {
	return string(self.sni)
}
func (self *TlsTLV) SetSNI(sni string) {
	self.sni = []byte(sni)
	self.flags = self.flags | PP2_CLIENT_SNI | PP2_CLIENT_SSL
}

func (self *TlsTLV) Certs() ([]*x509.Certificate, error) {
	return x509.ParseCertificates(self.certs)
}

func (self *TlsTLV) SetCerts(certs []*x509.Certificate) error {
	fp := make([]byte, len(certs[0].Signature))
	copy(fp, certs[0].Signature)
	var buf bytes.Buffer
	for _, cert := range certs {
		_, err := buf.Write(cert.Raw)
		if err != nil {
			return err
		}
	}
	self.certs = buf.Bytes()
	self.fp = fp
	return nil
}

func (self *TlsTLV) Fingerprint() []byte {
	if self.fp == nil {
		return nil
	}
	fp := make([]byte, len(self.fp))
	copy(fp, self.fp)
	return fp
}

func writeSubTLV(w io.Writer, recType byte, data []byte) error {
	prologue := new(bytes.Buffer)
	prologue.WriteByte(recType)
	err := binary.Write(prologue, binary.BigEndian, uint16(len(data)))
	if err != nil {
		return err
	}
	_, err = prologue.WriteTo(w)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func (self *TlsTLV) Size() uint16 {
	totalLength := 5

	if self.version != nil {
		totalLength += 3 + len(self.version)
	}
	if self.cn != nil {
		totalLength += 3 + len(self.cn)
	}
	if self.sni != nil {
		totalLength += 3 + len(self.sni)
	}
	if self.certs != nil {
		totalLength += 3 + len(self.certs)
	}
	if self.fp != nil {
		totalLength += 3 + len(self.fp)
	}

	return uint16(totalLength)
}

func (self *TlsTLV) WriteTo(w io.Writer) error {
	prologue := new(bytes.Buffer)
	prologue.WriteByte(PP2_TYPE_SSL)
	err := binary.Write(prologue, binary.BigEndian, self.Size())
	// I cannot fathom how this call could possibly fail, but let's be safe...
	if err != nil {
		return err
	}
	prologue.WriteByte(self.flags)
	err = binary.Write(prologue, binary.BigEndian, self.verification)
	// I cannot fathom how this call could possibly fail, but let's be safe...
	if err != nil {
		return err
	}
	_, err = prologue.WriteTo(w)
	if err != nil {
		return err
	}

	if self.version != nil {
		err = writeSubTLV(w, PP2_TYPE_SSL_VERSION, self.version)
		if err != nil {
			return err
		}
	}
	if self.cn != nil {
		err = writeSubTLV(w, PP2_TYPE_SSL_CN, self.cn)
		if err != nil {
			return err
		}
	}
	if self.sni != nil {
		err = writeSubTLV(w, PP2_TYPE_SSL_SNI, self.sni)
		if err != nil {
			return err
		}
	}
	if self.certs != nil {
		err = writeSubTLV(w, PP2_TYPE_SSL_CERT, self.certs)
		if err != nil {
			return err
		}
	}
	if self.fp != nil {
		err = writeSubTLV(w, PP2_TYPE_SSL_FP, self.fp)
		if err != nil {
			return err
		}
	}

	return nil
}

func HandleProxy(conn io.ReadWriter) (*ProxyInfo, []byte, error) {
	maybeHeader := make([]byte, len(ProxyProtoV2Header))
	bytesRead, err := conn.Read(maybeHeader)
	if err != nil {
		return nil, nil, err
	}
	if bytesRead < len(ProxyProtoV2Header) {
		// Not enough bytes for the header, so not using the Proxy Protocol v2.
		return nil, maybeHeader, nil
	}

	trailer := make([]byte, 4)
	bytesRead, err = conn.Read(trailer)
	if err != nil {
		return nil, nil, err
	}
	if bytesRead < 4 {
		return nil, nil, fmt.Errorf("Unable to read last 4 bytes of header (only read %d)", bytesRead)
	}

	byte13 := trailer[0]

	protoVersion := byte13 & 0xf0 >> 4
	if protoVersion != 0x2 {
		return nil, nil, fmt.Errorf("Bad proxy protocol version: %x", protoVersion)
	}
	protoCommand := byte13 & 0x0f

	var isLocal bool
	switch protoCommand {
	case 0x0:
		isLocal = true
	case 0x1:
		isLocal = false
	default:
		return nil, nil, fmt.Errorf("Bad proxy protocol command: %x", protoCommand)
	}

	byte14 := trailer[1]

	var addrSize int
	addrFamily := byte14 & 0xf0 >> 4
	switch addrFamily {
	case ADDR_FAMILY_UNSPEC:
		addrSize = 0
	case ADDR_FAMILY_INET4:
		addrSize = 12
	case ADDR_FAMILY_INET6:
		addrSize = 36
	case ADDR_FAMILY_UNIX:
		addrSize = 216
	default:
		return nil, nil, fmt.Errorf("Bad address family: %x", addrFamily)
	}
	transport := byte14 & 0x0f
	switch transport {
	case TRANSPORT_UNSPEC:
		break
	case TRANSPORT_STREAM:
		break
	case TRANSPORT_DGRAM:
		break
	default:
		return nil, nil, fmt.Errorf("Bad transport: %x", transport)
	}

	var totalLen uint16
	err = binary.Read(bytes.NewReader(trailer[2:4]), binary.BigEndian, &totalLen)
	if err != nil {
		return nil, nil, err
	}

	remainingBytes := make([]byte, totalLen)
	bytesRead, err = conn.Read(remainingBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read remaining header: %s", err.Error())
	}
	if uint(bytesRead) < uint(totalLen) {
		return nil, nil, fmt.Errorf("Connection failed to send full header!")
	}

	var addrBytes []byte
	if addrSize == 0 {
		addrBytes = nil
	} else {
		addrBytes = remainingBytes[0:addrSize]
		remainingBytes = remainingBytes[addrSize:]
	}

	tlvs := make([]TLV, 0)
	for {
		var tlv TLV
		tlv, remainingBytes, err = ParseTLV(remainingBytes)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, err
		}
		tlvs = append(tlvs, tlv)
		if len(remainingBytes) == 0 {
			break
		}
	}

	return &ProxyInfo{
		IsLocal: isLocal,
		AddrFamily: addrFamily,
		Transport: transport,
		AddrListBytes: addrBytes,
		TLVs: tlvs,
	}, nil, nil
}

type ProxyConn struct {
	reader io.Reader
	conn net.Conn
	info *ProxyInfo
}

func NewProxyConnIncoming(conn net.Conn) (*ProxyConn, error) {
	proxyInfo, bytesToWrite, err := HandleProxy(conn)
	if err != nil {
		return nil, err
	}

	var reader io.Reader = conn
	if bytesToWrite != nil {
		reader = io.MultiReader(bytes.NewReader(bytesToWrite), conn)
	}

	return &ProxyConn{
		reader: reader,
		conn: conn,
		info: proxyInfo,
	}, nil
}

func NewProxyConnOutgoing(conn net.Conn, proxyInfo *ProxyInfo) (*ProxyConn, error) {
	var reader io.Reader = conn
	err := proxyInfo.WriteTo(conn)
	if err != nil {
		return nil, err
	}
	return &ProxyConn{
		reader: reader,
		conn: conn,
		info: proxyInfo,
	}, nil
}

func (self *ProxyConn) Info() *ProxyInfo {
	return self.info
}

func (self *ProxyConn) Read(b []byte) (n int, err error) {
	return self.reader.Read(b)
}

func (self *ProxyConn) Write(b []byte) (n int, err error) {
	return self.conn.Write(b)
}

func (self *ProxyConn) Close() error {
	return self.conn.Close()
}

func (self *ProxyConn) LocalAddr() net.Addr {
	return self.conn.LocalAddr()
}

func (self *ProxyConn) RemoteAddr() net.Addr {
	return self.conn.RemoteAddr()
}

func (self *ProxyConn) SetDeadline(t time.Time) error {
	return self.conn.SetDeadline(t)
}

func (self *ProxyConn) SetReadDeadline(t time.Time) error {
	return self.conn.SetReadDeadline(t)
}

func (self *ProxyConn) SetWriteDeadline(t time.Time) error {
	return self.conn.SetWriteDeadline(t)
}
