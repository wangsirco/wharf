package panel

import (
	"net/http"
	"sort"
	"strconv"
	"time"
)

// Proxy usage for any period: "since this node was created", "yesterday",
// "the last 3 hours", a date range. Hours are kept 400 days (proxy_traffic),
// 5-minute buckets for the last few days (proxy_traffic_5m) so short recent
// periods are exact rather than rounded to whole hours.

const fineKeep = 3 * 86400

type usagePoint struct {
	T    int64 `json:"t"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type usagePart struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Gone    bool   `json:"gone,omitempty"`    // deleted since
	Others  bool   `json:"others,omitempty"`  // not visible to the caller, summed
	Created int64  `json:"created,omitempty"` //
}

type usageResp struct {
	From    int64        `json:"from"`
	To      int64        `json:"to"`
	Bucket  int64        `json:"bucket"` // 300 | 3600 | 86400
	Total   usagePoint   `json:"total"`
	Series  []usagePoint `json:"series"`
	By      []usagePart  `json:"by"`      // users of a node, nodes of a user, nodes for everything
	ByKind  string       `json:"by_kind"` // user | node
	Peak    *usagePoint  `json:"peak,omitempty"`
	Created int64        `json:"created,omitempty"` // when the node / user was created
	Kept    int64        `json:"kept"`              // oldest hour still kept
	Clipped bool         `json:"clipped,omitempty"` // the period starts before what is kept
}

// usageBucket picks the step: 5 minutes for short recent periods, hours up to 4 days, days beyond.
func usageBucket(from, to, now, fineSince int64) int64 {
	span := to - from
	switch {
	case fineSince > 0 && from >= fineSince && from >= now-fineKeep && span <= 12*3600:
		return 300
	case span <= 4*86400:
		return 3600
	default:
		return 86400
	}
}

// GET /api/proxy/usage?node=|user=&from=&to=  (unix seconds; to defaults to now)
func (a *App) handleProxyUsage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v := a.proxyVisibility(currentUser(r))
	now := time.Now().Unix()
	nodeID, _ := strconv.ParseInt(q.Get("node"), 10, 64)
	userID, _ := strconv.ParseInt(q.Get("user"), 10, 64)
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	if to <= 0 || to > now {
		to = now
	}
	out := usageResp{ByKind: "node", Series: []usagePoint{}, By: []usagePart{}}
	switch {
	case nodeID > 0:
		n := v.nodes[nodeID]
		if n == nil {
			jsonErr(w, 404, "没有这个节点")
			return
		}
		out.Created, out.ByKind = n.Created, "user"
	case userID > 0:
		p := v.users[userID]
		if p == nil {
			jsonErr(w, 404, "没有这个用户")
			return
		}
		out.Created = p.Created
	}
	var kept int64
	_ = a.db.QueryRow(`SELECT COALESCE(MIN(hour), 0) FROM proxy_traffic`).Scan(&kept)
	out.Kept = kept
	if from <= 0 { // "since the beginning"
		from = out.Created
		if from <= 0 {
			from = kept
		}
		if from <= 0 {
			from = now - 86400
		}
	}
	if from >= to {
		jsonErr(w, 400, "开始时间要早于结束时间")
		return
	}
	if kept > 0 && from < kept && (out.Created == 0 || out.Created < kept) {
		out.Clipped = true
	}
	var fineSince int64
	_ = a.db.QueryRow(`SELECT COALESCE(MIN(ts), 0) FROM proxy_traffic_5m`).Scan(&fineSince)
	out.Bucket = usageBucket(from, to, now, fineSince)

	// bucket starts
	var starts []int64
	switch out.Bucket {
	case 86400:
		for d := dayStartOf(from); d < to; d = dayStartOf(d + 36*3600) { // +36 h then back to midnight: safe across DST
			starts = append(starts, d)
		}
	default:
		for t := from / out.Bucket * out.Bucket; t < to; t += out.Bucket {
			starts = append(starts, t)
		}
	}
	if len(starts) > 2000 {
		jsonErr(w, 400, "时间段太长")
		return
	}
	idx := func(ts int64) int { // bucket index of a row timestamp
		i := sort.Search(len(starts), func(i int) bool { return starts[i] > ts }) - 1
		return i
	}
	series := make([]usagePoint, len(starts))
	for i, s := range starts {
		series[i].T = s
	}

	table, col, lo, hi := "proxy_traffic", "hour", from/3600*3600, to
	if out.Bucket == 300 {
		table, col, lo = "proxy_traffic_5m", "ts", from/300*300
	}
	rows, err := a.db.Query(`SELECT `+col+`, user_id, node_id, up, down FROM `+table+` WHERE `+col+` >= ? AND `+col+` < ?`, lo, hi)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	parts := map[int64]*usagePart{}
	var others usagePart
	exists := map[int64]bool{}
	existsMemo := func(id int64) bool {
		e, ok := exists[id]
		if !ok {
			e = a.proxyExists(out.ByKind, id)
			exists[id] = e
		}
		return e
	}
	for rows.Next() {
		var ts, uid, nid, up, down int64
		if rows.Scan(&ts, &uid, &nid, &up, &down) != nil {
			continue
		}
		if (nodeID > 0 && nid != nodeID) || (userID > 0 && uid != userID) {
			continue
		}
		if nodeID == 0 && userID == 0 && v.nodes[nid] == nil {
			continue // everything = the caller's nodes
		}
		if userID > 0 && v.nodes[nid] == nil && v.users[uid] == nil {
			continue
		}
		i := idx(ts)
		if i < 0 {
			continue
		}
		series[i].Up += up
		series[i].Down += down
		out.Total.Up += up
		out.Total.Down += down
		key := nid
		if out.ByKind == "user" {
			key = uid
		}
		visible := (out.ByKind == "user" && v.users[key] != nil) || (out.ByKind == "node" && v.nodes[key] != nil)
		if !visible && existsMemo(key) {
			others.Up += up
			others.Down += down
			continue
		}
		if parts[key] == nil {
			parts[key] = &usagePart{ID: key}
		}
		parts[key].Up += up
		parts[key].Down += down
	}
	out.Series = series
	for id, p := range parts {
		switch {
		case out.ByKind == "user" && v.users[id] != nil:
			p.Name, p.Created = v.users[id].Name, v.users[id].Created
		case out.ByKind == "node" && v.nodes[id] != nil:
			p.Name, p.Created = v.nodes[id].Name, v.nodes[id].Created
		default:
			p.Gone = true
			p.Name = map[string]string{"user": "已删除的用户", "node": "已删除的节点"}[out.ByKind] + " #" + strconv.FormatInt(id, 10)
		}
		out.By = append(out.By, *p)
	}
	if others.Up+others.Down > 0 {
		others.Others, others.Name = true, "其他管理员的"+map[string]string{"user": "用户", "node": "节点"}[out.ByKind]
		out.By = append(out.By, others)
	}
	sort.Slice(out.By, func(i, j int) bool { return out.By[i].Up+out.By[i].Down > out.By[j].Up+out.By[j].Down })
	for i := range series {
		if s := series[i]; s.Up+s.Down > 0 && (out.Peak == nil || s.Up+s.Down > out.Peak.Up+out.Peak.Down) {
			p := s
			out.Peak = &p
		}
	}
	out.From, out.To = from, to
	writeJSON(w, 200, out)
}

// proxyExists: the id still exists (so a row the caller can't see is someone else's, not a deleted one).
func (a *App) proxyExists(kind string, id int64) bool {
	table := "proxy_nodes"
	if kind == "user" {
		table = "proxy_users"
	}
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE id=?`, id).Scan(&n)
	return n > 0
}

// lifetime totals per node and per user (as far back as hours are kept), for the lists
func (a *App) proxyLifetime() (nodes, users map[int64]usagePoint) {
	nodes, users = map[int64]usagePoint{}, map[int64]usagePoint{}
	rows, err := a.db.Query(`SELECT user_id, node_id, SUM(up), SUM(down) FROM proxy_traffic GROUP BY user_id, node_id`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var uid, nid, up, down int64
		if rows.Scan(&uid, &nid, &up, &down) != nil {
			continue
		}
		n, u := nodes[nid], users[uid]
		n.Up, n.Down, u.Up, u.Down = n.Up+up, n.Down+down, u.Up+up, u.Down+down
		nodes[nid], users[uid] = n, u
	}
	return
}
