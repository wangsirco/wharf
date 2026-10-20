// owp-rulegen downloads the blackmatrix7 lists in rules.Catalog and writes the
// compiled rule file embedded into owp-panel (internal/rules/data/rules.json.gz).
package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/wangsirco/wharf/internal/oui"
	"github.com/wangsirco/wharf/internal/rules"
)

func main() {
	out := flag.String("o", "internal/rules/data/rules.json.gz", "output file")
	ouiOut := flag.String("oui", "internal/oui/data/oui.txt.gz", "OUI vendor output file")
	flag.Parse()
	if b, err := oui.Build(&http.Client{Timeout: 120 * time.Second}); err != nil {
		log.Printf("oui: %v (keeping existing file)", err)
	} else {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		zw.Write(b)
		zw.Close()
		if err := os.WriteFile(*ouiOut, buf.Bytes(), 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("oui: %d bytes\n", buf.Len())
	}
	c, err := rules.Build(&http.Client{Timeout: 60 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Write(*out); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("services=%d suffix=%d exact=%d keywords=%d cidrs=%d asn=%d missing=%v\n",
		len(c.Services), len(c.Suffix), len(c.Exact), len(c.Keywords), len(c.CIDRs), len(c.ASN), c.Missing)
}
