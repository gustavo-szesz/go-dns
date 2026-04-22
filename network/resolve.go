package network

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/gustavo-szesz/go-dns/dns"
)

// Resolve: por enquanto só monta a pergunta e faz 1 query (não recursivo).
func Resolve(domain string) string {
	question := dns.NewQuestion(domain, dns.TypeA, dns.ClassIN)
	flag := dns.NewHeaderFlag(false, 0, false, false, false, false, 0, 0).GenerateFlag()
	header := dns.NewHeader(22, flag, 1, 0, 0, 0)
	msg := dns.NewDNSMessage(*header, []dns.Question{*question})

	client := NewClient(dns.RootDNS, dns.RootDNSPort)
	resp, err := client.Query(msg.ToBytes())
	if err != nil {
		fmt.Printf("query failed: %v\n", err)
		return ""
	}

	parsed := dns.DNSMessageFromBytes(resp)
	if len(parsed.Answers) == 0 {
		return ""
	}
	return parsed.Answers[0].RDataParsed
}

func ResolveA(domain string, serverAddr string) (string, error) {
	records, err := ResolveARecords(domain, serverAddr)
	if err != nil {
		return "", err
	}
	return records[0], nil
}

// MXRecord represents one MX answer with its preference.
type MXRecord struct {
	Preference uint16
	Exchange   string
}

func ResolveMX(domain string, serverAddr string) ([]MXRecord, error) {
	parsed, err := queryDNS(domain, dns.TypeMX, serverAddr)
	if err != nil {
		return nil, err
	}
	return parseMXRecords(parsed)
}

func ResolveARecords(domain string, serverAddr string) ([]string, error) {
	parsed, err := queryDNS(domain, dns.TypeA, serverAddr)
	if err != nil {
		return nil, err
	}

	records := make([]string, 0)
	for _, ans := range parsed.Answers {
		if ans.Type == dns.TypeA && ans.RDataParsed != "" {
			records = append(records, ans.RDataParsed)
		}
	}
	records = uniqueStrings(records)

	if len(records) == 0 {
		return nil, fmt.Errorf("no A record in answers")
	}
	return records, nil
}

func ResolveAAAARecords(domain string, serverAddr string) ([]string, error) {
	parsed, err := queryDNS(domain, dns.TypeAAAA, serverAddr)
	if err != nil {
		return nil, err
	}

	records := make([]string, 0)
	for _, ans := range parsed.Answers {
		if ans.Type == dns.TypeAAAA && ans.RDataParsed != "" {
			records = append(records, ans.RDataParsed)
		}
	}
	records = uniqueStrings(records)

	if len(records) == 0 {
		return nil, fmt.Errorf("no AAAA record in answers")
	}
	return records, nil
}

func ResolveTXT(domain string, serverAddr string) ([]string, error) {
	parsed, err := queryDNS(domain, dns.TypeTXT, serverAddr)
	if err != nil {
		return nil, err
	}

	records := make([]string, 0)
	for _, ans := range parsed.Answers {
		if ans.Type == dns.TypeTXT && ans.RDataParsed != "" {
			records = append(records, ans.RDataParsed)
		}
	}
	records = uniqueStrings(records)

	if len(records) == 0 {
		return nil, fmt.Errorf("no TXT record in answers")
	}
	return records, nil
}

type MailMXRecord struct {
	Preference uint16
	Exchange   string
	IPv4       []string
	IPv6       []string
}

type MailDomainInfo struct {
	Domain      string
	SPF         []string
	DMARC       []string
	MX          []MailMXRecord
	NullMX      bool
	FallbackToA []string
}

func AnalyzeMailDomain(domain string, serverAddr string) (*MailDomainInfo, error) {
	domain = strings.TrimSuffix(domain, ".")

	info := &MailDomainInfo{Domain: domain}

	mxRecords, err := ResolveMX(domain, serverAddr)
	if err != nil {
		aRecords, aErr := ResolveARecords(domain, serverAddr)
		if aErr == nil && len(aRecords) > 0 {
			info.FallbackToA = aRecords
		} else {
			return nil, fmt.Errorf("resolve MX: %w", err)
		}
	} else {
		info.MX = make([]MailMXRecord, 0, len(mxRecords))
		for _, mx := range mxRecords {
			if mx.Exchange == "." {
				info.NullMX = true
				continue
			}

			aRecords, _ := ResolveARecords(mx.Exchange, serverAddr)
			aaaaRecords, _ := ResolveAAAARecords(mx.Exchange, serverAddr)

			info.MX = append(info.MX, MailMXRecord{
				Preference: mx.Preference,
				Exchange:   mx.Exchange,
				IPv4:       aRecords,
				IPv6:       aaaaRecords,
			})
		}
	}

	rootTXT, _ := ResolveTXT(domain, serverAddr)
	for _, txt := range rootTXT {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
			info.SPF = append(info.SPF, txt)
		}
	}

	dmarcTXT, _ := ResolveTXT("_dmarc."+domain, serverAddr)
	for _, txt := range dmarcTXT {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
			info.DMARC = append(info.DMARC, txt)
		}
	}

	return info, nil
}

func queryDNS(domain string, qType uint16, serverAddr string) (*dns.DNSMessage, error) {
	domain = strings.TrimSuffix(domain, ".")

	question := dns.NewQuestion(domain, qType, dns.ClassIN)
	flag := dns.NewHeaderFlag(false, 0, false, false, true, false, 0, 0).GenerateFlag() // RD=true
	header := dns.NewHeader(0x1234, flag, 1, 0, 0, 0)
	msg := dns.NewDNSMessage(*header, []dns.Question{*question})

	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial dns server: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(msg.ToBytes())
	if err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	parsed := dns.DNSMessageFromBytes(buf[:n])
	if len(parsed.Answers) == 0 {
		return nil, fmt.Errorf("no answers")
	}

	return parsed, nil
}

func parseMXRecords(parsed *dns.DNSMessage) ([]MXRecord, error) {
	records := make([]MXRecord, 0)
	for _, ans := range parsed.Answers {
		if ans.Type != dns.TypeMX || ans.RDataParsed == "" {
			continue
		}

		fields := strings.Fields(ans.RDataParsed)
		if len(fields) < 2 {
			continue
		}

		priority, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			continue
		}

		records = append(records, MXRecord{
			Preference: uint16(priority),
			Exchange:   fields[1],
		})
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no MX record in answers")
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Preference < records[j].Preference
	})

	return records, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		unique = append(unique, v)
	}
	return unique
}
