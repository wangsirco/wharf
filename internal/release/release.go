// Package release describes what a Wharf release contains, per component, so a running
// panel can fetch only what changed. The manifest is signed with an ed25519 key that
// never leaves the maintainer's machine; the public half is compiled into the panel.
package release

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ManifestName = "wharf-manifest.json"
	SigName      = "wharf-manifest.json.sig"
)

// Asset is one downloadable file of a release.
type Asset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest lists the release's components and their fingerprints.
//   - web:  the browser UI; can be swapped in at runtime without a restart.
//   - core: agent + panel + LuCI page, shipped as one ipk per architecture (it also carries the web UI).
type Manifest struct {
	Version  string `json:"version"`
	Released int64  `json:"released"`
	Web      struct {
		Hash  string `json:"hash"`
		Asset Asset  `json:"asset"`
	} `json:"web"`
	Core struct {
		Hash     string           `json:"hash"`
		Packages map[string]Asset `json:"packages"` // opkg architecture -> ipk
	} `json:"core"`
}

// Verify checks the detached base64 signature against the base64 public key.
func Verify(manifest, sig []byte, pubB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("更新公钥无效")
	}
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(pub, manifest, s) {
		return errors.New("更新清单签名校验失败：拒绝使用")
	}
	return nil
}

// Sign returns the base64 signature of data with a base64 ed25519 seed.
func Sign(data []byte, seedB64 string) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", errors.New("bad signing key")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), data)), nil
}

// WebHash fingerprints a built web UI: sha256 over "path\x00sha256(file)\n" of every file, sorted.
func WebHash(fsys fs.FS) (string, error) {
	var lines []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Base(p) == ".gitkeep" {
			return err
		}
		f, err := fsys.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		lines = append(lines, p+"\x00"+hex.EncodeToString(h.Sum(nil))+"\n")
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(h[:]), nil
}

// CoreHash fingerprints everything that goes into the binaries and the package except the web UI.
func CoreHash(root string) (string, error) {
	var lines []string
	for _, top := range []string{"cmd", "internal", "package", "go.mod", "go.sum"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasSuffix(p, "_test.go") || strings.HasPrefix(d.Name(), ".") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			lines = append(lines, fmt.Sprintf("%s\x00%x\n", filepath.ToSlash(rel), sha256.Sum256(b)))
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(h[:]), nil
}

// ExtractWeb unpacks a web bundle (tar.gz of the dist directory) into dir, refusing unsafe paths.
func ExtractWeb(r io.Reader, dir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	total := int64(0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." || strings.HasPrefix(name, "..") || path.IsAbs(name) {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if total += h.Size; total > 64<<20 {
				return errors.New("网页包过大")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			f.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// PackWeb writes a deterministic tar.gz of dir (used by the release tool).
func PackWeb(dir string, w io.Writer) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == ".gitkeep" {
			return err
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if err := tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return err
		}
		if _, err := tw.Write(b); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// PkgArch maps Go's GOARCH (+GOARM) to the opkg architecture the build script uses.
func PkgArch(goarch, goarm string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64_generic"
	case "arm":
		return "arm_cortex-a7_neon-vfpv4"
	case "mips":
		return "mips_24kc"
	case "mipsle":
		return "mipsel_24kc"
	}
	return goarch
}
