package main

import (
	"os"

	network "github.com/gustavo-szesz/go-dns/network"
)

func main() {
	// argLen := len(os.Args)
	// if argLen < 2 {
	// 	fmt.Println("Usage: go run main.go <domain> [OPT]")
	// 	fmt.Println("OPT: ")
	// 	fmt.Println(" --no-cache")
	// 	os.Exit(1)
	// }
	// domain := os.Args[1]
	// network.Resolve(domain, dns.TypeA)
	domain := os.Args[1]
	network.Resolve(domain)
}
