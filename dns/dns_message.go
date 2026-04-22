package dns

import (
	"bytes"
)

// DNSMessage represent DNS message (Header + sections)
type DNSMessage struct {
	Header        Header
	Questions     []Question
	Answers       []ResourceRecord
	AuthorityRRs  []ResourceRecord
	AdditionalRRs []ResourceRecord
}

// NewDNSMessage returns *DNSMessage
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

// ToBytes converts the DNSMessage into bytes.
func (m *DNSMessage) ToBytes() []byte {
	buf := new(bytes.Buffer)

	buf.Write(m.Header.ToBytes())

	for _, q := range m.Questions {
		buf.Write(q.ToBytes())
	}
	for _, a := range m.Answers {
		buf.Write(a.ToBytes())
	}
	for _, rr := range m.AuthorityRRs {
		buf.Write(rr.ToBytes())
	}
	for _, rr := range m.AdditionalRRs {
		buf.Write(rr.ToBytes())
	}

	return buf.Bytes()
}

// appendFromBufferUntilNull reads bytes from buffer until it reads 0x00 (inclusive).
func appendFromBufferUntilNull(buf *bytes.Buffer) []byte {
	data := make([]byte, 0)
	for {
		b := buf.Next(1)
		if len(b) == 0 {
			break
		}
		data = append(data, b[0])
		if b[0] == 0 {
			break
		}
	}
	return data
}

// DNSMessageFromBytes parses a DNS message from raw bytes.
func DNSMessageFromBytes(data []byte) *DNSMessage {
	buf := bytes.NewBuffer(data)
	bufCopy := bytes.NewBuffer(data)

	// Header (12 bytes)
	header := HeaderFromBytes(buf.Next(12))

	// Questions
	questions := make([]Question, header.QDCount)
	for i := 0; i < int(header.QDCount); i++ {
		qBytes := appendFromBufferUntilNull(buf)  // QNAME (ends with 0x00)
		qBytes = append(qBytes, buf.Next(4)...)   // QTYPE + QCLASS
		questions[i] = *QuestionFromBytes(qBytes) // parse question
	}

	// Answers
	answers := make([]ResourceRecord, header.ANCount)
	for i := 0; i < int(header.ANCount); i++ {
		rrBytes := TrimResourceRecordBytes(buf)
		answers[i] = *ResourceRecordFromBytes(rrBytes, bufCopy)
	}

	// Authority
	authorityRRs := make([]ResourceRecord, header.NSCount)
	for i := 0; i < int(header.NSCount); i++ {
		rrBytes := TrimResourceRecordBytes(buf)
		authorityRRs[i] = *ResourceRecordFromBytes(rrBytes, bufCopy)
	}

	// Additional
	additionalRRs := make([]ResourceRecord, header.ARCount)
	for i := 0; i < int(header.ARCount); i++ {
		rrBytes := TrimResourceRecordBytes(buf)
		additionalRRs[i] = *ResourceRecordFromBytes(rrBytes, bufCopy)
	}

	return &DNSMessage{
		Header:        *header,
		Questions:     questions,
		Answers:       answers,
		AuthorityRRs:  authorityRRs,
		AdditionalRRs: additionalRRs,
	}
}
