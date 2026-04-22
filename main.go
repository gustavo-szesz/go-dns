package main

import (
	"fmt"
	"os"

	"github.com/gustavo-szesz/go-dns/network"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <domain>")
		os.Exit(1)
	}

	domain := os.Args[1]
	ip, err := network.ResolveA(domain, "8.8.8.8:53")
	if err != nil {
		fmt.Printf("lookup failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s -> %s\n", domain, ip)
}
