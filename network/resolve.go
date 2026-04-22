package network

import (
	"fmt"
	"net"
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
	// normaliza: "google.com." -> "google.com"
	domain = strings.TrimSuffix(domain, ".")

	question := dns.NewQuestion(domain, dns.TypeA, dns.ClassIN)
	flag := dns.NewHeaderFlag(false, 0, false, false, true, false, 0, 0).GenerateFlag() // RD=true
	header := dns.NewHeader(0x1234, flag, 1, 0, 0, 0)
	msg := dns.NewDNSMessage(*header, []dns.Question{*question})

	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		return "", fmt.Errorf("dial dns server: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(msg.ToBytes())
	if err != nil {
		return "", fmt.Errorf("send query: %w", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	fmt.Printf("n=%d header=% x\n", n, buf[:12])
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	parsed := dns.DNSMessageFromBytes(buf[:n])
	if len(parsed.Answers) == 0 {
		return "", fmt.Errorf("no answers")
	}
	fmt.Printf("ANCOUNT=%d answers=%+v\n", parsed.Header.ANCount, parsed.Answers)
	// pega o primeiro A
	for _, ans := range parsed.Answers {
		if ans.Type == dns.TypeA && ans.RDataParsed != "" {
			return ans.RDataParsed, nil
		}
	}

	return "", fmt.Errorf("no A record in answers")
}
