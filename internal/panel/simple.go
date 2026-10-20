package panel

import (
	"net/http"
	"time"
)

// GET /api/simple/devices?range=today|7d — one call for the simple-mode device wall:
// per device how much it used, what kind of things, which services, and what it is
// doing right now (last hour).
func (a *App) handleSimpleDevices(w http.ResponseWriter, r *http.Request) {
	from, to := timeRange(r)
	recent := time.Now().Unix() - 3600
	recent -= recent % 3600
	type devSum struct {
		MAC        string `json:"mac"`
		Up         int64  `json:"up"`
		Down       int64  `json:"down"`
		Categories []*agg `json:"categories"`
		Services   []*agg `json:"services"`
		Now        []*agg `json:"now"`
	}
	out := map[string]*devSum{}
	get := func(mac string) *devSum {
		if out[mac] == nil {
			out[mac] = &devSum{MAC: mac}
		}
		return out[mac]
	}
	if rows, err := a.db.Query(`SELECT mac, SUM(up), SUM(down) FROM traffic_hour WHERE hour>=? AND hour<? GROUP BY mac`, from-from%3600, to); err == nil {
		for rows.Next() {
			var mac string
			var up, down int64
			if rows.Scan(&mac, &up, &down) == nil {
				d := get(mac)
				d.Up, d.Down = up, down
			}
		}
		rows.Close()
	}
	if currentUser(r).Can("traffic.view") {
		cats, svcs, now := map[string]aggMap{}, map[string]aggMap{}, map[string]aggMap{}
		rows, err := a.db.Query(`SELECT mac, domain, remote, SUM(up+down), SUM(CASE WHEN hour>=? THEN up+down ELSE 0 END)
			FROM flow_hour WHERE hour>=? AND hour<? AND inbound=0 GROUP BY mac, domain, remote`, recent, from-from%3600, to)
		if err == nil {
			for rows.Next() {
				var mac, domain, remote string
				var b, rb int64
				if rows.Scan(&mac, &domain, &remote, &b, &rb) != nil {
					continue
				}
				id := a.identify(domain, remote)
				name := svcName(id)
				for _, m := range []map[string]aggMap{cats, svcs, now} {
					if m[mac] == nil {
						m[mac] = aggMap{}
					}
				}
				cats[mac].add(id.Category, func() *agg { return &agg{Name: id.Category} }, func(x *agg) { x.Bytes += b })
				svcs[mac].add(name, func() *agg { return id.newAgg(name) }, func(x *agg) { x.Bytes += b })
				if rb > 0 {
					now[mac].add(name, func() *agg { return id.newAgg(name) }, func(x *agg) { x.Bytes += rb })
				}
			}
			rows.Close()
		}
		for mac := range cats {
			d := get(mac)
			d.Categories, d.Services, d.Now = cats[mac].top(5, byBytes), svcs[mac].top(5, byBytes), now[mac].top(3, byBytes)
		}
	}
	list := make([]*devSum, 0, len(out))
	for _, d := range out {
		list = append(list, d)
	}
	writeJSON(w, 200, list)
}
