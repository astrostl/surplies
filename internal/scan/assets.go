package scan

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
)

// Defensive format validation from ByteGuard's masquerade checks. These extra
// formats are not asserted to be confirmed DUNE carriers.
// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts
var assetMagics = map[string][][]byte{
	".png": {{137, 80, 78, 71, 13, 10, 26, 10}}, ".jpg": {{255, 216, 255}}, ".jpeg": {{255, 216, 255}},
	".gif": {[]byte("GIF87a"), []byte("GIF89a")}, ".ico": {{0, 0, 1, 0}}, ".wasm": {{0, 97, 115, 109, 1, 0, 0, 0}},
	".pdf": {[]byte("%PDF-")}, ".zip": {{80, 75, 3, 4}, {80, 75, 5, 6}, {80, 75, 7, 8}},
	".mp3": {[]byte("ID3"), {255, 251}, {255, 243}, {255, 242}}, ".webp": {}, ".mp4": {},
}

func assetExtension(ext string) bool {
	_, ok := assetMagics[ext]
	return ok || slices.Contains(fontExtensions, ext)
}
func validAsset(ext string, data []byte) bool {
	if slices.Contains(fontExtensions, ext) {
		return hasFontMagic(data)
	}
	if ext == ".webp" {
		return len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP"
	}
	if ext == ".mp4" {
		return len(data) >= 12 && string(data[4:8]) == "ftyp"
	}
	for _, magic := range assetMagics[ext] {
		if bytes.HasPrefix(data, magic) {
			return true
		}
	}
	return false
}

// Bounded by the shared whole-file cap/deadline, including long padded prefixes.
func trimAssetPadding(data []byte) []byte { return bytes.TrimLeft(data, "\x00 \t\r\n\v\f") }
func (s *Scanner) checkDisguisedAsset(path, ext string, data []byte) {
	if !assetExtension(ext) || validAsset(ext, data) {
		return
	}
	clean := trimAssetPadding(data)
	if looksLikeHTML(clean) {
		return
	}
	detail := "Declared asset format has an unrecognized or truncated header; may be corrupt or an unsupported variant"
	if looksLikeText(clean) {
		detail = "Binary-named asset contains text; may be a disguised script, inspect before use"
	}
	s.addFinding(Finding{Check: "asset-format-mismatch", Severity: SevWarn, Path: path, Detail: detail})
}
func taskAsset(path string) bool {
	ext := strings.ToLower(filepath.Ext(strings.Trim(path, `"'`)))
	return assetExtension(ext) || slices.Contains([]string{".bin", ".dat", ".svg"}, ext)
}
