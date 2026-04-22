package dns

import (
	"bytes"
	"encoding/binary"
)

// 4.1.1. Header section format
//
// The header contains the following fields:
//
//	                                1  1  1  1  1  1
//	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                      ID                       |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                    QDCOUNT                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                    ANCOUNT                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                    NSCOUNT                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                    ARCOUNT                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type Header struct {
	ID      uint16 // ID is 16 bit identifier assigned bu the program that genenaretes the kind of query
	Flags   uint16 // Flags contains various control Flags for the DNSMESSAGE
	QDCount uint16 // QDCount specifies the number of etries in the question section
	ANCount uint16 // ANCount specifies the number of resource records in the anser section
	NSCount uint16 // NSCount specifies the number of name server resource records in the authority system section
	ARCount uint16 // ARCount specifies the number of resource records in the additional records section
}

func NewHeader(id, flags, qdCount, anCount, nsCount, arCount uint16) *Header {
	return &Header{
		ID:      id,
		Flags:   flags,
		QDCount: qdCount,
		ANCount: anCount,
		NSCount: nsCount,
		ARCount: arCount,
	}
}

func (h *Header) ToBytes() []byte {
	buf := new(byte.Buffer)

	binary.Write(buf, binary.BigEndian, h.ID)
	binary.Write(buf, binary.BigEndian, h.Flags)
	binary.Write(buf, binary.BigEndian, h.QDCount)
	binary.Write(buf, binary.BigEndian, h.ANCount)
	binary.Write(buf, binary.BigEndian, h.NSCount)
	binary.Write(buf, binary.BigEndian, h.ARCount)

	return buf.Bytes()
}

// Creates Headers instance from its byte representation
func HeaderFromBytes(b []byte) *Header {
	buf := bytes.NewReader(b)

	var id, flags, qdCount, anCount, nsCount, arCount uint16

	binary.Read(buf, binary.BigEndian, &id)
	binary.Read(buf, binary.BigEndian, &flags)
	binary.Read(buf, binary.BigEndian, &qdCount)
	binary.Read(buf, binary.BigEndian, &anCount)
	binary.Read(buf, binary.BigEndian, &nsCount)
	binary.Read(buf, binary.BigEndian, &arCount)

	return &Header{
		ID:      id,
		Flags:   flags,
		QDCount: qdCount,
		ANCount: anCount,
		NSCount: nsCount,
		ARCount: arCount,
	}
}
