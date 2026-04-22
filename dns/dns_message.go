package dns

import (
	"bytes"
)

// DNSMessage represent DNS DNSMessage
// It means: it contains the Header, Questions, Answers, AuthorityRRs amd AdditionalRRs
// =================== OFICIAL Docs ========================================
// All communications inside of the domain protocol are carried in a single
// format called a message.  The top level format of message is divided
// into 5 sections (some of which are empty in certain cases) shown below:
//
//	+---------------------+
//	|        Header       |
//	+---------------------+
//	|       Question      | the question for the name server
//	+---------------------+
//	|        Answer       | RRs answering the question
//	+---------------------+
//	|      Authority      | RRs pointing toward an authority
//	+---------------------+
//	|      Additional     | RRs holding additional information
//	+---------------------+
//
// The header section is always present.  The header includes fields that
// specify which of the remaining sections are present, and also specify
// whether the message is a query or a response, a standard query or some
// other opcode, etc.
//
// The names of the sections after the header are derived from their use in
// standard queries.  The question section contains fields that describe a
// question to a name server.  These fields are a query type (QTYPE), a
// query class (QCLASS), and a query domain name (QNAME).  The last three
// sections have the same format: a possibly empty list of concatenated
// resource records (RRs).  The answer section contains RRs that answer the
// question; the authority section contains RRs that point toward an
// authoritative name server; the additional records section contains RRs
// which relate to the query, but are not strictly answers for the
// question.
type DNSMessage struct {
	Header        Header
	Questions     []Question
	Answers       []ResourceRecord
	AuthorityRRs  []ResourceRecord
	AdditionalRRs []ResourceRecord
}

// NewDNSMessage retuns *DNSMessage
func NewDNSMessage(header Header, questions []Questions, records ...[]ResourceRecord) *DNSMessage {
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

// ToBytes is a casting of the DNSMessage into a ByteSlice
// Returns the byte slice representation of the DNSMessage
func (m *DNSMessage) ToBytes() []byte {
	// New Buffer to store the bytes
	buf := new(bytes.Buffer)

	// Write tje header into the new buffer
	buf.Write(m.Header.ToBytes())

	// Write the questions to the buffer
	for _, q := range m.Questions {
		buf.Write(q.ToBytes())
	}

	// Write the Answers into the buffer
	for _, a := range m.Answers {
		buf.Write(a.ToBytes())
	}

	// Write the AuthorityRRs into the buffer
	for _, rr := range m.AuthorityRRs {
		buf.Write(rr.ToBytes())
	}

	// Write AdditionalRRs into the buffer
	for _, rr := range m.AdditionalRRs {
		buf.Write(rr.ToBytes())
	}

	return buf.Bytes()
}

// appenFromBufferUntilNull reads bytes from buffer until null
// return read bytes as a bytes slice.
func appenFromBufferUntilNull(buf *bytes.Buffer) []byte {
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

// DNSMessage from Bytes creates a DNSMessage from given bytes slice
// return &DNSMessage
func DNSMessageFromBytes(data []byte) *DNSMessage {
	buf := bytes.NewBuffer(data)
	bufCopy := bytes.NewBuffer(data)

	// Read the header from the buffer
	header := HeaderFromBytes(buf.Next(12))

	// Read the question from the buffer
	questions := make([]Questions, header.QDCount)
	for i := 0; i < int(header.QDCount); i++ {
		questionsBytes := appenFromBufferUntilNull(buf)
		questionsBytes = append(questionsBytes, buf.Next(4)...)
		questions[i] = *ResourceRecordFromBytes(rrBytes, bufCopy)
	}

	answers := make([]ResourceRecord, header.ANCount)
	for i := 0; i < int(header.ANCount); i++ {
		rrBytes := TrimResourceRecordBytes(buf)
		answers[i] = *ResourceRecordFromBytes(rrBytes, bufCopy)
	}

	authorityRRs := make([]ResourceRecord, header.NSCount)
	for i := 0; i < int(header.ARCount); i++ {
		rrBytes := TrimResourceRecordBytes(buf)
		authorityRRs[i] := *ResourceRecordFromBytes(rrBytes, bufCopy)
	}

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
