package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/gustavo-szesz/go-dns/network"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <domain> [A|MX|MAIL]")
		os.Exit(1)
	}

	domain := os.Args[1]
	recordType := "A"
	if len(os.Args) >= 3 {
		recordType = strings.ToUpper(os.Args[2])
	}

	switch recordType {
	case "A":
		ip, err := network.ResolveA(domain, "8.8.8.8:53")
		if err != nil {
			fmt.Printf("lookup failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s A -> %s\n", domain, ip)
	case "MX":
		mxRecords, err := network.ResolveMX(domain, "8.8.8.8:53")
		if err != nil {
			fmt.Printf("lookup failed: %v\n", err)
			os.Exit(1)
		}
		for _, mx := range mxRecords {
			fmt.Printf("%s MX -> %d %s\n", domain, mx.Preference, mx.Exchange)
		}
	case "MAIL":
		info, err := network.AnalyzeMailDomain(domain, "8.8.8.8:53")
		if err != nil {
			fmt.Printf("lookup failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("domain: %s\n", info.Domain)
		if info.NullMX {
			fmt.Println("mx: null-mx (domain does not accept email)")
		}
		for _, mx := range info.MX {
			fmt.Printf("mx: %d %s\n", mx.Preference, mx.Exchange)
			if len(mx.IPv4) > 0 {
				fmt.Printf("  ipv4: %s\n", strings.Join(mx.IPv4, ", "))
			}
			if len(mx.IPv6) > 0 {
				fmt.Printf("  ipv6: %s\n", strings.Join(mx.IPv6, ", "))
			}
		}
		if len(info.FallbackToA) > 0 {
			fmt.Printf("fallback-a: %s\n", strings.Join(info.FallbackToA, ", "))
		}
		for _, spf := range info.SPF {
			fmt.Printf("spf: %s\n", spf)
		}
		for _, dmarc := range info.DMARC {
			fmt.Printf("dmarc: %s\n", dmarc)
		}
	default:
		fmt.Printf("unsupported record type: %s (use A, MX or MAIL)\n", recordType)
		os.Exit(1)
	}
}
