package agent

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseXORMappedAddress(t *testing.T) {
	// Build a XOR-MAPPED-ADDRESS for 203.0.113.5:51820
	ip := net.ParseIP("203.0.113.5").To4()
	port := uint16(51820)

	data := make([]byte, 8)
	data[0] = 0x00 // reserved
	data[1] = 0x01 // family: IPv4

	// XOR port with magic cookie high 16 bits
	xPort := port ^ uint16(stunMagic>>16)
	binary.BigEndian.PutUint16(data[2:4], xPort)

	// XOR IP with magic cookie
	magicBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBytes, stunMagic)
	for i := 0; i < 4; i++ {
		data[4+i] = ip[i] ^ magicBytes[i]
	}

	result, err := parseXORMappedAddress(data)
	if err != nil {
		t.Fatalf("parseXORMappedAddress: %v", err)
	}
	if result != "203.0.113.5:51820" {
		t.Errorf("expected 203.0.113.5:51820, got %s", result)
	}
}

func TestParseMappedAddress(t *testing.T) {
	ip := net.ParseIP("10.0.0.1").To4()
	data := make([]byte, 8)
	data[0] = 0x00 // reserved
	data[1] = 0x01 // family: IPv4
	binary.BigEndian.PutUint16(data[2:4], 12345)
	copy(data[4:8], ip)

	result, err := parseMappedAddress(data)
	if err != nil {
		t.Fatalf("parseMappedAddress: %v", err)
	}
	if result != "10.0.0.1:12345" {
		t.Errorf("expected 10.0.0.1:12345, got %s", result)
	}
}

func TestParseSTUNResponse(t *testing.T) {
	// Build a complete STUN Binding Success Response with XOR-MAPPED-ADDRESS
	ip := net.ParseIP("192.0.2.1").To4()
	port := uint16(3478)

	// Build attribute
	attr := make([]byte, 12)                      // 4 header + 8 value
	binary.BigEndian.PutUint16(attr[0:2], 0x0020) // XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(attr[2:4], 8)      // length
	attr[4] = 0x00                                // reserved
	attr[5] = 0x01                                // IPv4

	xPort := port ^ uint16(stunMagic>>16)
	binary.BigEndian.PutUint16(attr[6:8], xPort)

	magicBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBytes, stunMagic)
	for i := 0; i < 4; i++ {
		attr[8+i] = ip[i] ^ magicBytes[i]
	}

	// Build header
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], 0x0101)            // Binding Success Response
	binary.BigEndian.PutUint16(header[2:4], uint16(len(attr))) // message length
	binary.BigEndian.PutUint32(header[4:8], stunMagic)

	data := append(header, attr...)

	result, err := parseSTUNResponse(data)
	if err != nil {
		t.Fatalf("parseSTUNResponse: %v", err)
	}
	if result != "192.0.2.1:3478" {
		t.Errorf("expected 192.0.2.1:3478, got %s", result)
	}
}

func TestParseSTUNResponseBadType(t *testing.T) {
	data := make([]byte, 20)
	binary.BigEndian.PutUint16(data[0:2], 0x0111) // wrong type
	binary.BigEndian.PutUint32(data[4:8], stunMagic)

	_, err := parseSTUNResponse(data)
	if err == nil {
		t.Error("expected error for wrong message type")
	}
}

func TestParseSTUNResponseBadMagic(t *testing.T) {
	data := make([]byte, 20)
	binary.BigEndian.PutUint16(data[0:2], 0x0101)
	binary.BigEndian.PutUint32(data[4:8], 0xDEADBEEF) // wrong magic

	_, err := parseSTUNResponse(data)
	if err == nil {
		t.Error("expected error for wrong magic cookie")
	}
}

func TestParseXORMappedAddressTooShort(t *testing.T) {
	_, err := parseXORMappedAddress([]byte{0, 1, 0, 0})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestParseXORMappedAddressIPv6(t *testing.T) {
	data := make([]byte, 8)
	data[1] = 0x02 // IPv6 family
	_, err := parseXORMappedAddress(data)
	if err == nil {
		t.Error("expected error for IPv6 family")
	}
}
