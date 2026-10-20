package panel

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type AgentConfig struct {
	URL         string `json:"url"`         // http://127.0.0.1:7071 or https://router:7071
	KeyID       string `json:"key_id"`      // from the router plugin
	Secret      string `json:"secret"`      //
	Fingerprint string `json:"fingerprint"` // required for https: pinned agent cert sha256
}

type Config struct {
	Listen         string      `json:"listen"`          // :7080
	TLS            string      `json:"tls"`             // "auto" (self-signed) | "off" | "files"
	CertFile       string      `json:"cert_file"`       // for tls=files
	KeyFile        string      `json:"key_file"`        //
	DataDir        string      `json:"data_dir"`        // database, geo db, certs
	TrustedProxies []string    `json:"trusted_proxies"` // CIDRs whose X-Forwarded-For / CF-Connecting-IP is trusted
	Agent          AgentConfig `json:"agent"`
}

func DefaultConfig() Config {
	return Config{Listen: ":7080", TLS: "auto", DataDir: "/mnt/data/owp", Agent: AgentConfig{URL: "http://127.0.0.1:7071"}}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func (c Config) Path(name ...string) string {
	return filepath.Join(append([]string{c.DataDir}, name...)...)
}
