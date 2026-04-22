package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Question represnt DNS Question
//
// The question section is used to carry the "question" in most queries,
// i.e., the parameters that define what is being asked.  The section
// contains QDCOUNT (usually 1) entries, each of the following format:
//
//	                                1  1  1  1  1  1
//	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                                               |
//	/                     QNAME                     /
//	/                                               /
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     QTYPE                     |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     QCLASS                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type Question struct {
	Name   string // Domain name
	QName  string // RFC 1035
	QType  uint16 // Question type
	QClass uint16 // Question class1
}

// NewQuestion creates a new Question instance with the specified parameters.
func NewQuestion(name string, qType, qClass uint16) *Question {
	q := &Question{
		Name:   name,
		QType:  qType,
		QClass: qClass,
	}
	q.QName = encodeName(name)
	return q
}

// SetName sets the domain name of the Question and updates the converted domain name.
func (q *Question) SetName(name string) {
	q.Name = name
	q.QName = encodeName(name)
}

// encodeName encodes the domain name to the format specified in RFC 1035.
func encodeName(name string) string {
	domainParts := strings.Split(name, ".")
	qname := ""
	for _, part := range domainParts {
		newDomainPart := string(byte(len(part))) + part
		qname += newDomainPart
	}
	return qname + "\x00"
}

// DecodeName decodes the encoded domain name to its original format.
func DecodeName(qname string, messageBufs ...*bytes.Buffer) (string, error) {
	encoded := []byte(qname)
	var result bytes.Buffer
	var messageBuf *bytes.Buffer
	if messageBufs != nil {
		messageBuf = messageBufs[0]
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

// ToBytes converts the Question to its byte representation.
func (q *Question) ToBytes() []byte {
	buf := new(bytes.Buffer)

	buf.Write([]byte(q.QName))
	binary.Write(buf, binary.BigEndian, q.QType)
	binary.Write(buf, binary.BigEndian, q.QClass)

	return buf.Bytes()
}

// QuestionFromBytes creates a Question instance from its byte representation.
func QuestionFromBytes(b []byte) *Question {
	length := len(b)
	qname := string(b[:length-4])

	name, _ := DecodeName(qname)

	return &Question{
		Name:   name,
		QName:  qname,
		QType:  binary.BigEndian.Uint16(b[length-4 : length-2]),
		QClass: binary.BigEndian.Uint16(b[length-2:]),
	}
}
