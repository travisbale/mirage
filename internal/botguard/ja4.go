// Package botguard provides TLS ClientHello fingerprinting (JA4) and
// heuristic-based bot detection scoring.
//
// Bot detection operates in two layers:
//   - L1: Known-bad JA4 signature lookup (deterministic, per-connection).
//     Handled by [aitm.BotGuardService] using signatures from this package.
//   - L2: Behavioral heuristics from browser telemetry (probabilistic,
//     configurable threshold). Implemented by [Scorer].
package botguard

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// TLS record and handshake type constants.
const (
	tlsRecordTypeHandshake  = 0x16
	tlsHandshakeClientHello = 0x01
)

// TLS extension type IDs.
const (
	extServerName        = 0x0000
	extSupportedGroups   = 0x000a
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
)

// greaseValues contains all GREASE values defined in RFC 8701.
// These are filtered out before computing JA4 hashes.
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// parsedHello holds the fields extracted from a raw TLS ClientHello record
// needed to compute the JA4 fingerprint.
type parsedHello struct {
	TLSVersion      uint16   // highest supported version (from supported_versions ext if present)
	CipherSuites    []uint16 // wire order, GREASE included (filtered during hash)
	Extensions      []uint16 // extension type IDs in wire order, GREASE included
	SupportedGroups []uint16 // from supported_groups extension, GREASE included
	HasSNI          bool
	ALPNLast        string // last protocol in ALPN extension list
}

// ComputeJA4 parses helloBytes and returns the JA4 fingerprint string.
// Format: t<TLSver><SNI><#Ciphers><#Exts><ALPN>_<CipherHash>_<ExtGroupHash>
// Example: "t13d0505h2_1234567890ab_abcdef123456"
//
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

	ciphers := filterGREASE(parsed.CipherSuites)
	extensions := filterGREASE(parsed.Extensions)
	groups := filterGREASE(parsed.SupportedGroups)

	alpnLabel := "00"
	if parsed.ALPNLast != "" && len(parsed.ALPNLast) >= 2 {
		alpnLabel = parsed.ALPNLast[:2]
	}

	partA := fmt.Sprintf("t%s%s%02d%02d%s", tlsVer, sniChar, len(ciphers), len(extensions), alpnLabel)

	// --- Part B: cipher suite hash ---
	slices.Sort(ciphers)
	partB := hashAndTruncate(joinUint16s(ciphers, ","))

	// --- Part C: extension + curve hash ---
	slices.Sort(extensions)
	slices.Sort(groups)

	combined := joinUint16s(extensions, ",") + "_" + joinUint16s(groups, ",")
	partC := hashAndTruncate(combined)

	return partA + "_" + partB + "_" + partC, nil
}

// parseClientHello parses the raw bytes of a TLS ClientHello record.
// The record format is: 5-byte TLS record header + 4-byte handshake header + ClientHello body.
//
// For TLS 1.3, if a supported_versions extension is present, its highest
// non-GREASE version overrides the legacy_version field. Extensions are
// optional; a ClientHello without extensions is valid.
func parseClientHello(b []byte) (*parsedHello, error) {
	// Minimum: 5 (record hdr) + 4 (hs hdr) + 2 (client_version) + 32 (random)
	// + 1 (session_id_len) + 2 (cipher_suites_len) + 1 (compression_methods_len) = 47
	if len(b) < 47 {
		return nil, fmt.Errorf("too short: %d bytes", len(b))
	}
	if b[0] != tlsRecordTypeHandshake {
		return nil, fmt.Errorf("not a TLS handshake record (got 0x%02x)", b[0])
	}
	if b[5] != tlsHandshakeClientHello {
		return nil, fmt.Errorf("not a ClientHello (got 0x%02x)", b[5])
	}

	// Skip: record header (5) + handshake header (4); then read legacy_version (2).
	parsed := &parsedHello{
		TLSVersion: binary.BigEndian.Uint16(b[5+4 : 5+4+2]),
	}

	// Skip: record header (5) + handshake header (4) + legacy_version (2) + random (32).
	offset := 5 + 4 + 2 + 32

	// Session ID (variable length, skip).
	if offset >= len(b) {
		return nil, fmt.Errorf("truncated at session_id_len")
	}
	sidLen := int(b[offset])
	offset++
	if offset+sidLen > len(b) {
		return nil, fmt.Errorf("truncated in session_id")
	}
	offset += sidLen

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
		case extServerName:
			parsed.HasSNI = true
		case extSupportedGroups:
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[:2]))
				for i := 2; i+1 < 2+listLen; i += 2 {
					group := binary.BigEndian.Uint16(extData[i : i+2])
					parsed.SupportedGroups = append(parsed.SupportedGroups, group)
				}
			}
		case extALPN:
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
		case extSupportedVersions:
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

// filterGREASE returns vals with all GREASE values (RFC 8701) removed.
func filterGREASE(vals []uint16) []uint16 {
	var out []uint16
	for _, v := range vals {
		if !greaseValues[v] {
			out = append(out, v)
		}
	}
	return out
}

func hashAndTruncate(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:12]
}

func joinUint16s(vals []uint16, sep string) string {
	parts := make([]string, len(vals))
	for i, val := range vals {
		parts[i] = strconv.FormatUint(uint64(val), 10)
	}
	return strings.Join(parts, sep)
}
