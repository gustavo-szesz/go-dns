package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h *Header) ToBytes() []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, h.ID)
	binary.Write(buffer, binary.BigEndian, h.Flags)
	binary.Write(buffer, binary.BigEndian, h.QDCount)
	binary.Write(buffer, binary.BigEndian, h.ANCount)
	binary.Write(buffer, binary.BigEndian, h.NSCount)
	binary.Write(buffer, binary.BigEndian, h.ANCount)

	return buffer.Bytes()
}

type HeaderFlag struct {
	QR     bool  // Query
	Opcode uint8 // Type of Query
	AA     bool  // Name server
	TC     bool  // Message is truncade
	RD     bool  // Recursion is required
	RA     bool  // Recursion is avaliable in the server
	Z      uint8 // Reserved for future usage
	RCode  uint8 // Response Code
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (hf *HeaderFlag) GenerateFlag() uint16 {
	qr := uint16(boolToInt(hf.QR))
	opcode := uint16(hf.Opcode)
	aa := uint16(boolToInt(hf.AA))
	tc := uint16(boolToInt(hf.TC))
	rd := uint16(boolToInt(hf.RD))
	ra := uint16(boolToInt(hf.RA))
	z := uint16(hf.Z)
	rcode := uint16(hf.RCode)

	return uint16(qr<<15 | opcode<<11 | aa<<10 | tc<<9 | rd<<8 | ra<<7 | z<<4 | rcode)
}

type Question struct {
	Name   string // Domain Name
	QName  string // Convert name RFC 1035 document
	QType  uint16 // Question type
	QClass uint16 // Question QClass
}

func encodeName(name string) string {
	domainParts := strings.Split(name, ".")
	qname := ""
	for _, part := range domainParts {
		newDomainPart := string(byte(len(part))) + part
		qname += newDomainPart
	}
	return qname + '\x00'
}

func (q *Question) ToBytes() []byte {
	buffer := new(bytes.Buffer)
	buffer.Write([]byte(q.QName))
	binary.Write(buffer, binary.BigEndian, q.QType)
	binary.Write(buffer, binary.BigEndian, q.QClass)
	return buffer.Bytes()
}

type DNSMessage struct {
	Header        Header
	Questions     []Question
	Answers       []ResourceRecord
	AuthorityRRs  []ResourceRecord
	AdditionalRRs []ResourceRecord
}

func NewDNSMessage(header Header, questions []Question, records ...[]ResourceRecord) *DNSMessage {
	answers := make([]ResourceRecord, 0)
	authorityRRs := make([]ResourceRecord, 0)
	additionalRRs := make([]ResourceRecord, 0)

	if len(records) > 0 {
		answers = records[0]
	}
	if len(records) > 1 {
		authorityRRs = records[1]
	}
	if len(records) > 2 {
		additionalRRs = records[2]
	}

	return &DNSMessage{
		Header:        header,
		Questions:     questions,
		Answers:       answers,
		AuthorityRRs:  authorityRRs,
		AdditionalRRs: additionalRRs,
	}
}

type Client struct {
	ipAddress string
	port      int
}

func (c *Client) Query(message []byte) ([]byte, error) {
	ipType, err := c.ipType()
	var addr string
	if err != nil {
		return nil, fmt.Errorf("Failed to get the IP type: %v", err)
	}

	if ipType == "ipv4" {
		addr = fmt.Sprintf("%s:%d", c.ipAddress, c.port)
	} else if ipType == "ipv6" {
		addr = fmt.Sprintf("[%s]:%d", c.ipAddress, c.port)
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to the DNS server: %v", err)
	}

	defer conn.Close()

	// Define a timout for the connection
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send message
	_, err = conn.Write(message)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the DNS message: %v", err)
	}

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the response message: %v", err)
	}

	response := buf[:n]

	if !IDMatcher(message[:2], response[:2]) {
		return nil, fmt.Errorf("The response ID does not match: %v", err)
	}

	return response, nil
}

type ResourceRecord struct {
	Name        string
	Type        uint16
	Class       uint16
	TTL         uint32
	RDLength    uint16
	RData       []byte
	RDataParsed string
}

func appendFromBufferUntilNull(buf *bytes.Buffer) []byte {
	// Create a bytes slice by reading the bytes until we reach a null byte for any string field
	data := make([]byte, 0)
	for {
		b := buf.Next(1)
		data = append(data, b[0])
		if b[0] == 0 {
			break
		}
	}
	return data
}

func ResourceRecordFromBytes(data []byte, messageBufs ...*bytes.Buffer) *ResourceRecord {
	buf := bytes.NewBuffer(data)
	var messageBuf *bytes.Buffer
	if messageBufs != nil {
		messageBuf = messageBufs[0]
	}

	name := appendFromBufferUntilNull(buf)
	nameLength := len(name) - 1
	decodedName, err := DecodeName(string(name), messageBuf)
	if err != nil {
		fmt.Printf("Failed to decode the name: %v\n", err)
	}

	typ := binary.BigEndian.Uint16(data[nameLength:nameLength])
	class := binary.BigEndian.Uint16(data[nameLength+2 : nameLength+4])
	ttl := binary.BigEndian.Uint32(data[nameLength+4 : nameLength+8])
	rdLength := binary.BigEndian.Uint16(data[nameLength+8 : nameLength+10])
	rData := data[nameLength+10 : nameLength+10+int(rdLength)] // 10 is the length of the fields before RData
	rDataParsed, _ := parseRData(typ, rData, messageBuf)

	return &ResourceRecord{
		Name:        decodedName,
		Type:        typ,
		Class:       class,
		TTL:         ttl,
		RDLength:    rdLength,
		RData:       rData,
		RDataParsed: rDataParsed,
	}
}

func DecodeName(qname string, messageBufs ...*bytes.Buffer) (string, error) {
	encoded := []byte(qname)
	var result bytes.Buffer
	var messageBuf *bytes.Buffer
	if messageBufs != nil {
		messageBufs = messageBufs[0]
	}

	for i := 0; i < len(encoded); {
		length := int(encoded[i])
		if length == 0 {
			break
		}

		if encoded[i]>>6 == 0b11 && messageBuf != nil {
			// Check if the name is a pointer. Parse the pointer, get the offset and parse the name from the offset.
			// See https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4 for more information
			b := encoded[i+1]
			offset := int(b & 0b11111111)
			messageBytes := messageBuf.Bytes()
			messageBytes = messageBytes[offset:]
			name := appendFromBufferUntilNull(bytes.NewBuffer(messageBytes))
			n, _ := DecodeName(string(name))
			name = []byte(n)
			length = len(name)
			if result.Len() > 0 {
				result.WriteByte('.')
			}
			result.Write(name)
			i += length
			break
		}
		i++

		if i+length > len(encoded) {
			return "", fmt.Errorf("invalid encoded domain name")
		}
		if result.Len() > 0 {
			result.WriteByte('.')
		}
		result.Write(encoded[i : i+length])
		i += length
	}
	return result.String(), nil
}

func main() {
	fmt.Println("Resolving DNS")

	// Resolving
	// This is a p* version, just calling the function, brainrot
	// host := "google.com"

	//ips, err := net.LookupHost(host)
	//if err != nil {
	//fmt.Fprintln(os.Stderr, "Error to Resolving %s: %v\n", host, err)
	//return
	//}

	//for _, ip := range ips {
	//fmt.Println(ip)
	//}
}
