package dns

// ROOT dns Server
const (
	RootDNS     = "198.41.0.4"
	RootDNSPort = 53
)

const (
	TypeA     uint16 = 1   // IPV4 address record
	TypeNS    uint16 = 2   // authoritative name server record
	TypeCNAME uint16 = 5   // Canonical TypeCNAME
	TypeSOA   uint16 = 6   // Start Of authoritative record
	TypePTR   uint16 = 12  // Pointer
	TypeMX    uint16 = 15  // Mail exchanged name
	TypeTXT   uint16 = 16  // TEXT record
	TypeAAAA  uint16 = 28  // IPV6 address
	TypeSRV   uint16 = 33  // service locator record
	TypeOPT   uint16 = 41  // option record
	TypeAXFR  uint16 = 252 // transfer of a entire zone record
	TypeMAILB uint16 = 253 // Mailbox records (MB, MG, MR)
	TypeMAILA uint16 = 254 // mail agent RRs (OBSOLETE)
	TypeAll   uint16 = 255 // All records

)

const (
	ClassIN  uint16 = 1   // Internet class
	ClassCS  uint16 = 2   // CSNET class
	ClassCH  uint16 = 3   // CHAOS class
	ClassHS  uint16 = 4   // Hesiod [Dyer ]
	ClassAll uint16 = 255 // All Classes
)

const (
	RCodeNoError        uint8 = 0 // No error
	RCodeFormatError    uint8 = 1 // Format error - THe name server was unable to interpret the query
	RCodeServerFailure  uint8 = 2 // Server faliure - The name server was unable to process the query with the name server
	RCodeNameError      uint8 = 3 // Name error - Meaningful only for response from authoritative name server, == the domain name referenced in the query does NOT exist
	RCodeNotImplemented uint8 = 4 // Not implemented - The name server does not support this kind of query
	RCodeRefused        uint8 = 5 // Refused - The name server refuses to perform the specified operation for policy reason
)
