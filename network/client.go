package network

import (
	"fmt"
	"net"
	"time"
)

// Client represents a UDP client for sending DNS queries.
type Client struct {
	ipAddress string
	port      int
}

func NewClient(addr string, port int) *Client {
	return &Client{ipAddress: addr, port: port}
}

func (c *Client) ipType() (string, error) {
	ip := net.ParseIP(c.ipAddress)
	if ip.To4() != nil {
		return "ipv4", nil
	} else if ip.To16() != nil {
		return "ipv6", nil
	}
	return "", fmt.Errorf("invalid IP address: %s", c.ipAddress)
}

// Query sends a DNS message and returns the raw response bytes.
func (c *Client) Query(message []byte) ([]byte, error) {
	ipType, err := c.ipType()
	if err != nil {
		return nil, fmt.Errorf("failed to get the IP type: %v", err)
	}

	var addr string
	if ipType == "ipv4" {
		addr = fmt.Sprintf("%s:%d", c.ipAddress, c.port)
	} else {
		addr = fmt.Sprintf("[%s]:%d", c.ipAddress, c.port)
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the DNS server: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write(message)
	if err != nil {
		return nil, fmt.Errorf("failed to send the DNS message: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response: %v", err)
	}

	response := buf[:n]
	if !IDMatcher(message[:2], response[:2]) {
		return nil, fmt.Errorf("the response ID does not match the request ID")
	}

	return response, nil
}

func IDMatcher(m1, m2 []byte) bool {
	return m1[0] == m2[0] && m1[1] == m2[1]
}
