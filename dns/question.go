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
	QName  string // RFC 1035 (encoded name)
	QType  uint16 // Question type
	QClass uint16 // Question class
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
	name = strings.TrimSuffix(name, ".")
	domainParts := strings.Split(name, ".")
	qname := ""
	for _, part := range domainParts {
		if part == "" {
			continue
		}
		qname += string(byte(len(part))) + part
	}
	return qname + "\x00"
}

// DecodeName decodes the encoded domain name to its original format.
// Supports RFC1035 name compression pointers (0b11xxxxxx xxxxxxxx).
func DecodeName(qname string, messageBufs ...*bytes.Buffer) (string, error) {
	encoded := []byte(qname)

	var result bytes.Buffer
	var messageBuf *bytes.Buffer
	if messageBufs != nil {
		messageBuf = messageBufs[0]
	}

	for i := 0; i < len(encoded); {
		if i >= len(encoded) {
			break
		}

		// compression pointer: two bytes, first two bits are 11
		if (encoded[i] >> 6) == 0b11 {
			if messageBuf == nil {
				return "", fmt.Errorf("name compression pointer encountered but message buffer not provided")
			}
			if i+1 >= len(encoded) {
				return "", fmt.Errorf("invalid compression pointer (truncated)")
			}

			offset := (int(encoded[i]&0x3F) << 8) | int(encoded[i+1])
			msg := messageBuf.Bytes()
			if offset < 0 || offset >= len(msg) {
				return "", fmt.Errorf("compression pointer out of range: %d", offset)
			}

			pointed := msg[offset:]
			nameBytes := appendFromBufferUntilNull(bytes.NewBuffer(pointed))

			n, err := DecodeName(string(nameBytes), messageBuf)
			if err != nil {
				return "", err
			}
			if n != "" {
				if result.Len() > 0 {
					result.WriteByte('.')
				}
				result.WriteString(n)
			}
			break // pointer terminates the current name
		}

		length := int(encoded[i])
		if length == 0 {
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
	_ = binary.Write(buf, binary.BigEndian, q.QType)
	_ = binary.Write(buf, binary.BigEndian, q.QClass)

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
