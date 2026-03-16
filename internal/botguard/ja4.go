package botguard

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// greaseValues contains all GREASE values defined in RFC 8701.
// These are filtered out before computing JA4 hashes.
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// ParsedHello holds the fields extracted from a raw TLS ClientHello record
// needed to compute the JA4 fingerprint.
type ParsedHello struct {
	TLSVersion      uint16   // highest supported version (from supported_versions ext if present)
	CipherSuites    []uint16 // wire order, GREASE included (filtered during hash)
	Extensions      []uint16 // extension type IDs in wire order, GREASE included
	SupportedGroups []uint16 // from supported_groups extension, GREASE included
	HasSNI          bool
	ALPNLast        string // last protocol in ALPN extension list
}

// ComputeJA4 parses helloBytes and returns the JA4 fingerprint string of the
// form "t13d1516h2_<cipherhash>_<exthash>".
// Returns an empty string and a non-nil error if helloBytes is not a valid ClientHello.
func ComputeJA4(helloBytes []byte) (string, error) {
	parsed, err := parseClientHello(helloBytes)
	if err != nil {
		return "", fmt.Errorf("ja4: parse: %w", err)
	}

	// --- Part A: human-readable descriptor ---

	var tlsVer string
	switch parsed.TLSVersion {
	case 0x0304:
		tlsVer = "13"
	case 0x0303:
		tlsVer = "12"
	case 0x0302:
		tlsVer = "11"
	case 0x0301:
		tlsVer = "10"
	default:
		tlsVer = fmt.Sprintf("%02x", parsed.TLSVersion&0x00ff)
	}

	sniChar := "i" // i = IP / no SNI
	if parsed.HasSNI {
		sniChar = "d" // d = domain
	}

	cipherCount := 0
	for _, cipherSuite := range parsed.CipherSuites {
		if !greaseValues[cipherSuite] {
			cipherCount++
		}
	}
	extCount := 0
	for _, extType := range parsed.Extensions {
		if !greaseValues[extType] {
			extCount++
		}
	}

	alpnLabel := "00"
	if parsed.ALPNLast != "" && len(parsed.ALPNLast) >= 2 {
		alpnLabel = parsed.ALPNLast[:2]
	}

	partA := fmt.Sprintf("t%s%s%02d%02d%s", tlsVer, sniChar, cipherCount, extCount, alpnLabel)

	// --- Part B: cipher suite hash ---
	var ciphers []uint16
	for _, cipherSuite := range parsed.CipherSuites {
		if !greaseValues[cipherSuite] {
			ciphers = append(ciphers, cipherSuite)
		}
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	partB := truncHash(joinUint16s(ciphers, ","))

	// --- Part C: extension + curve hash ---
	var filteredExts []uint16
	for _, extType := range parsed.Extensions {
		if !greaseValues[extType] {
			filteredExts = append(filteredExts, extType)
		}
	}
	sort.Slice(filteredExts, func(i, j int) bool { return filteredExts[i] < filteredExts[j] })

	var filteredGroups []uint16
	for _, group := range parsed.SupportedGroups {
		if !greaseValues[group] {
			filteredGroups = append(filteredGroups, group)
		}
	}
	sort.Slice(filteredGroups, func(i, j int) bool { return filteredGroups[i] < filteredGroups[j] })

	combined := joinUint16s(filteredExts, ",") + "_" + joinUint16s(filteredGroups, ",")
	partC := truncHash(combined)

	return partA + "_" + partB + "_" + partC, nil
}

// parseClientHello parses the raw bytes of a TLS ClientHello record.
// The record starts with the TLS record header (5 bytes) followed by the
// handshake message header (4 bytes) followed by the ClientHello body.
func parseClientHello(b []byte) (*ParsedHello, error) {
	// Minimum: 5 (record hdr) + 4 (hs hdr) + 2 (client_version) + 32 (random)
	// + 1 (session_id_len) + 2 (cipher_suites_len) + 1 (compression_methods_len) = 47
	if len(b) < 47 {
		return nil, fmt.Errorf("too short: %d bytes", len(b))
	}
	if b[0] != 0x16 { // ContentType: Handshake
		return nil, fmt.Errorf("not a TLS handshake record (got 0x%02x)", b[0])
	}
	if b[5] != 0x01 { // HandshakeType: ClientHello
		return nil, fmt.Errorf("not a ClientHello (got 0x%02x)", b[5])
	}

	// Skip: record header (5) + handshake header (4); then read legacy_version (2).
	parsed := &ParsedHello{
		TLSVersion: binary.BigEndian.Uint16(b[5+4 : 5+4+2]),
	}

	// Skip: record header (5) + handshake header (4) + legacy_version (2) + random (32).
	offset := 5 + 4 + 2 + 32

	// Session ID (variable length, skip).
	if offset >= len(b) {
		return nil, fmt.Errorf("truncated at session_id_len")
	}
	sidLen := int(b[offset])
	offset += 1 + sidLen

	// Cipher suites.
	if offset+2 > len(b) {
		return nil, fmt.Errorf("truncated at cipher_suites_len")
	}
	csLen := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	if offset+csLen > len(b) {
		return nil, fmt.Errorf("truncated in cipher_suites")
	}
	for i := 0; i+1 < csLen; i += 2 {
		cipherSuite := binary.BigEndian.Uint16(b[offset+i : offset+i+2])
		parsed.CipherSuites = append(parsed.CipherSuites, cipherSuite)
	}
	offset += csLen

	// Compression methods (skip).
	if offset >= len(b) {
		return nil, fmt.Errorf("truncated at compression_methods_len")
	}
	compLen := int(b[offset])
	offset += 1 + compLen

	// Extensions.
	if offset+2 > len(b) {
		return parsed, nil // no extensions — valid for some very old clients
	}
	extsLen := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	end := offset + extsLen

	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(b[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(b[offset+2 : offset+4]))
		offset += 4
		extData := b[offset : offset+extLen]
		offset += extLen

		parsed.Extensions = append(parsed.Extensions, extType)

		switch extType {
		case 0x0000: // server_name
			parsed.HasSNI = true
		case 0x000a: // supported_groups
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[:2]))
				for i := 2; i+1 < 2+listLen; i += 2 {
					group := binary.BigEndian.Uint16(extData[i : i+2])
					parsed.SupportedGroups = append(parsed.SupportedGroups, group)
				}
			}
		case 0x0010: // application_layer_protocol_negotiation
			// ALPN list: 2-byte outer length, then 1-byte proto length + proto string.
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[:2]))
				pos := 2
				for pos < 2+listLen {
					protoLen := int(extData[pos])
					pos++
					if pos+protoLen <= len(extData) {
						parsed.ALPNLast = string(extData[pos : pos+protoLen])
					}
					pos += protoLen
				}
			}
		case 0x002b: // supported_versions
			// Override TLSVersion with the highest non-GREASE value from this extension.
			if len(extData) >= 1 {
				listLen := int(extData[0])
				for i := 1; i+1 < 1+listLen; i += 2 {
					version := binary.BigEndian.Uint16(extData[i : i+2])
					if !greaseValues[version] && version > parsed.TLSVersion {
						parsed.TLSVersion = version
					}
				}
			}
		}
	}

	return parsed, nil
}

func truncHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:12]
}

func joinUint16s(vals []uint16, sep string) string {
	parts := make([]string, len(vals))
	for i, val := range vals {
		parts[i] = fmt.Sprintf("%d", val)
	}
	return strings.Join(parts, sep)
}
