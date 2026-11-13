package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Importing a plugin: Wharf takes the plugin over and converts all of its LuCI
// pages to Wharf's form model once, up front, instead of every time a page is
// opened. JavaScript views can only run in a browser (the sandbox iframe), so the
// browser that clicks "导入" does the conversion and hands the result here.
//
// Only the page structure is kept: every "values" member is dropped before
// storing, so no setting (and no password) sits in Wharf's database. When a page
// opens, the current values are read from uci and laid over the structure; a quiet
// re-conversion then refreshes the structure for next time.

type importedPage struct {
	Path   string          `json:"path"`
	Title  string          `json:"title"`
	Kind   string          `json:"kind"`
	Target string          `json:"target"`
	Status string          `json:"status"` // ok | custom | failed
	Error  string          `json:"error,omitempty"`
	Blocks json.RawMessage `json:"blocks,omitempty"`
}

type pluginImport struct {
	Pkg       string         `json:"pkg"`
	Version   string         `json:"version"`
	At        int64          `json:"imported_at"`
	By        string         `json:"imported_by"`
	Refreshed int64          `json:"refreshed_at"`
	Pages     []importedPage `json:"pages"`
}

var pkgNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,80}$`)

// stripValues removes every "values" member from a JSON tree.
func stripValues(v any) any {
	switch t := v.(type) {
	case map[string]any:
		delete(t, "values")
		for k, x := range t {
			t[k] = stripValues(x)
		}
	case []any:
		for i, x := range t {
			t[i] = stripValues(x)
		}
	}
	return v
}

func cleanBlocks(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if _, ok := v.([]any); !ok {
		return nil, errors.New("blocks must be a list")
	}
	return json.Marshal(stripValues(v))
}

// importsMeta: pkg -> {version, imported_at}, for the plugin list.
func (a *App) importsMeta() map[string]map[string]any {
	out := map[string]map[string]any{}
	rows, err := a.db.Query(`SELECT pkg, version, imported_at, pages FROM plugin_imports`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var pkg, ver, pages string
		var at int64
		if rows.Scan(&pkg, &ver, &at, &pages) != nil {
			continue
		}
		var ps []importedPage
		_ = json.Unmarshal([]byte(pages), &ps)
		ok, custom, failed := 0, 0, 0
		for _, p := range ps {
			switch p.Status {
			case "ok":
				ok++
			case "custom":
				custom++
			default:
				failed++
			}
		}
		out[pkg] = map[string]any{"version": ver, "at": at, "ok": ok, "custom": custom, "failed": failed}
	}
	return out
}

func (a *App) loadImport(pkg string) (*pluginImport, error) {
	var p pluginImport
	var pages string
	err := a.db.QueryRow(`SELECT pkg, version, imported_at, imported_by, refreshed_at, pages FROM plugin_imports WHERE pkg=?`, pkg).
		Scan(&p.Pkg, &p.Version, &p.At, &p.By, &p.Refreshed, &pages)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(pages), &p.Pages); err != nil {
		return nil, err
	}
	return &p, nil
}

// GET /api/plugins/import?pkg=
func (a *App) handlePluginImportGet(w http.ResponseWriter, r *http.Request) {
	pkg := r.URL.Query().Get("pkg")
	p, err := a.loadImport(pkg)
	if errors.Is(err, sql.ErrNoRows) {
		jsonErr(w, 404, "这个插件还没有导入")
		return
	}
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func readBig(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(v)
}

// POST /api/plugins/import {pkg, version, pages}: the whole plugin (first import or re-import)
func (a *App) handlePluginImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pkg     string         `json:"pkg"`
		Version string         `json:"version"`
		Pages   []importedPage `json:"pages"`
	}
	if err := readBig(r, &req); err != nil || !pkgNameRe.MatchString(req.Pkg) {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	pl, err := a.pluginOf(req.Pkg)
	if err != nil || pl == nil {
		jsonErr(w, 404, "没有安装这个插件")
		return
	}
	known := map[string]bool{}
	for _, g := range pl.Pages {
		known[g.Path] = true
	}
	var pages []importedPage
	for _, p := range req.Pages {
		if !known[p.Path] || (p.Status != "ok" && p.Status != "custom" && p.Status != "failed") {
			continue
		}
		b, err := cleanBlocks(p.Blocks)
		if err != nil {
			p.Status, p.Error, b = "failed", "转换结果无法读取", nil
		}
		p.Blocks = b
		p.Error = truncate(p.Error, 300)
		pages = append(pages, p)
	}
	js, _ := json.Marshal(pages)
	u := currentUser(r)
	now := time.Now().Unix()
	if _, err := a.db.Exec(`INSERT INTO plugin_imports(pkg, version, imported_at, imported_by, pages, refreshed_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(pkg) DO UPDATE SET version=excluded.version, imported_at=excluded.imported_at, imported_by=excluded.imported_by, pages=excluded.pages, refreshed_at=excluded.refreshed_at`,
		req.Pkg, pl.Version, now, u.Username, string(js), now); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	ok := 0
	for _, p := range pages {
		if p.Status == "ok" {
			ok++
		}
	}
	a.audit(actor{user: u, ip: a.clientIP(r)}, "plugin.import", "plugin", req.Pkg, "导入插件 "+req.Pkg+"（"+strconv.Itoa(ok)+"/"+strconv.Itoa(len(pages))+" 个页面已转换）", nil, nil, false)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// PUT /api/plugins/import/page {pkg, page}: a quiet re-conversion refreshes one page
func (a *App) handlePluginImportPage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pkg  string       `json:"pkg"`
		Page importedPage `json:"page"`
	}
	if err := readBig(r, &req); err != nil {
		jsonErr(w, 400, "请求格式错误")
		return
	}
	p, err := a.loadImport(req.Pkg)
	if err != nil {
		jsonErr(w, 404, "这个插件还没有导入")
		return
	}
	b, err := cleanBlocks(req.Page.Blocks)
	if err != nil || req.Page.Status != "ok" {
		jsonErr(w, 400, "转换结果无法读取")
		return
	}
	found := false
	for i := range p.Pages {
		if p.Pages[i].Path == req.Page.Path {
			p.Pages[i].Blocks, p.Pages[i].Status, p.Pages[i].Error = b, "ok", ""
			found = true
		}
	}
	if !found {
		jsonErr(w, 404, "没有这个页面")
		return
	}
	js, _ := json.Marshal(p.Pages)
	_, _ = a.db.Exec(`UPDATE plugin_imports SET pages=?, refreshed_at=? WHERE pkg=?`, string(js), time.Now().Unix(), req.Pkg)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// DELETE /api/plugins/import?pkg=: hand the plugin back to LuCI
func (a *App) handlePluginUnimport(w http.ResponseWriter, r *http.Request) {
	pkg := r.URL.Query().Get("pkg")
	res, err := a.db.Exec(`DELETE FROM plugin_imports WHERE pkg=?`, pkg)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		a.audit(actor{user: currentUser(r), ip: a.clientIP(r)}, "plugin.unimport", "plugin", pkg, "取消导入插件 "+pkg, nil, nil, false)
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
