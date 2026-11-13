package panel

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

var migrations = []string{
	`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,              -- super | admin
		perms TEXT NOT NULL DEFAULT '[]', -- JSON array of permission keys
		quotas TEXT NOT NULL DEFAULT '{}',-- JSON object quota -> int
		disabled INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		last_login_at INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE sessions (
		token_hash TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		csrf TEXT NOT NULL,
		ip TEXT NOT NULL,
		user_agent TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		seen_at INTEGER NOT NULL
	)`,
	`CREATE TABLE audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		username TEXT NOT NULL,
		ip TEXT NOT NULL,
		action TEXT NOT NULL,       -- e.g. user.update, device.static.save
		target_type TEXT NOT NULL,  -- user | setting | uci
		target_id TEXT NOT NULL,    -- user id, setting key, config.section
		summary TEXT NOT NULL,
		before TEXT,                -- JSON
		after TEXT,                 -- JSON
		approval_id INTEGER,        -- set if executed via approval
		restorable INTEGER NOT NULL DEFAULT 0,
		restored_by INTEGER,
		restored_at INTEGER,
		restore_of INTEGER          -- audit id this entry restored
	)`,
	`CREATE INDEX audit_ts ON audit(ts)`,
	`CREATE TABLE approvals (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		username TEXT NOT NULL,
		ip TEXT NOT NULL,
		action TEXT NOT NULL,
		summary TEXT NOT NULL,
		payload TEXT NOT NULL,
		status TEXT NOT NULL,       -- pending | approved | rejected | expired | failed
		decided_by INTEGER,
		decided_at INTEGER,
		note TEXT NOT NULL DEFAULT '',
		result TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE visitors (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		user_id INTEGER,
		username TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL,
		asn INTEGER NOT NULL DEFAULT 0,
		as_org TEXT NOT NULL DEFAULT '',
		country TEXT NOT NULL DEFAULT '',
		region TEXT NOT NULL DEFAULT '',
		city TEXT NOT NULL DEFAULT '',
		ip_tz TEXT NOT NULL DEFAULT '',
		ip_offset INTEGER,          -- minutes east of UTC at ts, null if unknown
		client_tz TEXT NOT NULL DEFAULT '',
		client_offset INTEGER,      -- minutes east of UTC reported by browser
		client_time TEXT NOT NULL DEFAULT '',
		tz_match TEXT NOT NULL,     -- match | mismatch | unknown
		user_agent TEXT NOT NULL DEFAULT '',
		path TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX visitors_ts ON visitors(ts)`,
	`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
	// router objects created through the panel and who owns them (isolation between admins)
	`CREATE TABLE owned (
		config TEXT NOT NULL,
		section TEXT NOT NULL,
		kind TEXT NOT NULL,        -- static_host | forward | ...
		user_id INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (config, section)
	)`,
	// v2: panel access control + client-side ip.sb check
	`ALTER TABLE visitors ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE visitors ADD COLUMN reason TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE visitors ADD COLUMN mac TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE visitors ADD COLUMN ipsb TEXT NOT NULL DEFAULT ''`,       // JSON reported by the browser (untrusted)
	`ALTER TABLE visitors ADD COLUMN ipsb_match TEXT NOT NULL DEFAULT ''`, // same | diff | empty (ip.sb IP vs server-seen IP)
	// v3: traffic statistics (device = MAC; "ip:<addr>" when the MAC is unknown)
	`CREATE TABLE traffic_min (minute INTEGER NOT NULL, mac TEXT NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL,
		PRIMARY KEY (mac, minute)) WITHOUT ROWID`,
	`CREATE TABLE traffic_hour (hour INTEGER NOT NULL, mac TEXT NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL,
		PRIMARY KEY (mac, hour)) WITHOUT ROWID`,
	`CREATE INDEX traffic_hour_h ON traffic_hour(hour)`,
	`CREATE TABLE flow_hour (hour INTEGER NOT NULL, mac TEXT NOT NULL, remote TEXT NOT NULL, port INTEGER NOT NULL,
		proto TEXT NOT NULL, inbound INTEGER NOT NULL, domain TEXT NOT NULL DEFAULT '',
		up INTEGER NOT NULL, down INTEGER NOT NULL, conns INTEGER NOT NULL,
		PRIMARY KEY (mac, hour, remote, port, proto, inbound)) WITHOUT ROWID`,
	`CREATE INDEX flow_hour_h ON flow_hour(hour)`,
	`CREATE TABLE dns_hour (hour INTEGER NOT NULL, mac TEXT NOT NULL, domain TEXT NOT NULL,
		count INTEGER NOT NULL, blocked INTEGER NOT NULL, PRIMARY KEY (mac, hour, domain)) WITHOUT ROWID`,
	`CREATE INDEX dns_hour_h ON dns_hour(hour)`,
	`CREATE TABLE devices_seen (mac TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
		first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)`,
	`CREATE TABLE probes (target TEXT PRIMARY KEY, domain TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
		summary TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL)`,
	// v4: NextDNS enrichment (why a domain was blocked, tracker owner)
	`CREATE TABLE nextdns_domains (domain TEXT PRIMARY KEY, status TEXT NOT NULL, reasons TEXT NOT NULL DEFAULT '',
		tracker TEXT NOT NULL DEFAULT '', last_seen INTEGER NOT NULL, hits INTEGER NOT NULL DEFAULT 0)`,
	// v5: panel-side device names / types
	`CREATE TABLE device_meta (mac TEXT PRIMARY KEY, alias TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT '',
		note TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL)`,
	// v6: probes made before error-page titles were filtered named sites "403 Forbidden"; re-probe
	`DELETE FROM probes`,
	// v7: network quality, WAN events, speed tests
	`CREATE TABLE netq_min (minute INTEGER NOT NULL, target TEXT NOT NULL, sent INTEGER NOT NULL, lost INTEGER NOT NULL,
		min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, jitter REAL NOT NULL, PRIMARY KEY (target, minute)) WITHOUT ROWID`,
	`CREATE INDEX netq_min_m ON netq_min(minute)`,
	`CREATE TABLE wan_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL)`,
	`CREATE TABLE speedtests (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, down REAL NOT NULL, up REAL NOT NULL,
		latency REAL NOT NULL, server TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '')`,
	// v8: alerts
	`CREATE TABLE alert_channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)`,
	`CREATE TABLE alert_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL,
		body TEXT NOT NULL, result TEXT NOT NULL)`,
	// v9: per-user port forward grants (port ranges per WAN, LAN target ranges)
	`ALTER TABLE users ADD COLUMN grants TEXT NOT NULL DEFAULT '{}'`,
	// v10-11: device presence (left / back on the network)
	`CREATE TABLE device_presence (mac TEXT PRIMARY KEY, state TEXT NOT NULL, last_seen INTEGER NOT NULL, changed_at INTEGER NOT NULL)`,
	`CREATE TABLE device_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, mac TEXT NOT NULL, ip TEXT NOT NULL,
		kind TEXT NOT NULL, away_secs INTEGER NOT NULL DEFAULT 0);
	 CREATE INDEX device_events_mac ON device_events(mac, ts); CREATE INDEX device_events_ts ON device_events(ts)`,
	// v12-13: scheduled ping / TCP monitors
	`CREATE TABLE monitors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, target TEXT NOT NULL, mode TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 0, count INTEGER NOT NULL DEFAULT 10, interval_min INTEGER NOT NULL DEFAULT 5,
		loss_alert INTEGER NOT NULL DEFAULT 20, rtt_alert INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
		state TEXT NOT NULL DEFAULT 'unknown', state_since INTEGER NOT NULL DEFAULT 0, created_by INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE monitor_results (id INTEGER PRIMARY KEY AUTOINCREMENT, monitor_id INTEGER NOT NULL, ts INTEGER NOT NULL,
		sent INTEGER NOT NULL, recv INTEGER NOT NULL, min REAL NOT NULL DEFAULT 0, avg REAL NOT NULL DEFAULT 0, max REAL NOT NULL DEFAULT 0,
		jitter REAL NOT NULL DEFAULT 0, ip TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '');
	 CREATE INDEX monitor_results_mt ON monitor_results(monitor_id, ts)`,
	// v14: finished inbound connections through port forwards
	`CREATE TABLE fwd_conns (id INTEGER PRIMARY KEY AUTOINCREMENT, start INTEGER NOT NULL, end INTEGER NOT NULL, ip TEXT NOT NULL,
		mac TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL, proto TEXT NOT NULL, remote TEXT NOT NULL, rport INTEGER NOT NULL DEFAULT 0,
		up INTEGER NOT NULL, down INTEGER NOT NULL);
	 CREATE INDEX fwd_conns_target ON fwd_conns(ip, port, end); CREATE INDEX fwd_conns_end ON fwd_conns(end)`,
	// v15: proxy extension (nodes, proxy users, hourly traffic, access records, source IPs)
	`CREATE TABLE proxy_nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
		protocol TEXT NOT NULL, transport TEXT NOT NULL, security TEXT NOT NULL, entry TEXT NOT NULL, port INTEGER NOT NULL, wan TEXT NOT NULL DEFAULT '',
		domain TEXT NOT NULL DEFAULT '', params TEXT NOT NULL DEFAULT '{}', note TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL, updated INTEGER NOT NULL);
	 CREATE TABLE proxy_users (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, name TEXT NOT NULL, secret TEXT NOT NULL,
		sub_token TEXT NOT NULL UNIQUE, nodes TEXT NOT NULL DEFAULT '[]', limit_bytes INTEGER NOT NULL DEFAULT 0, reset_day INTEGER NOT NULL DEFAULT 0,
		expire_at INTEGER NOT NULL DEFAULT 0, ip_limit INTEGER NOT NULL DEFAULT 0, allow_lan INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
		stopped TEXT NOT NULL DEFAULT '', used_up INTEGER NOT NULL DEFAULT 0, used_down INTEGER NOT NULL DEFAULT 0, period_at INTEGER NOT NULL DEFAULT 0,
		note TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
	 CREATE TABLE proxy_traffic (hour INTEGER NOT NULL, user_id INTEGER NOT NULL, node_id INTEGER NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL,
		PRIMARY KEY (hour, user_id, node_id));
	 CREATE TABLE proxy_access (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, last INTEGER NOT NULL, user_id INTEGER NOT NULL,
		node_id INTEGER NOT NULL, ip TEXT NOT NULL, dest TEXT NOT NULL, port INTEGER NOT NULL, net TEXT NOT NULL, status TEXT NOT NULL, count INTEGER NOT NULL);
	 CREATE INDEX proxy_access_ts ON proxy_access(ts); CREATE INDEX proxy_access_user ON proxy_access(user_id, ts);
	 CREATE TABLE proxy_ips (user_id INTEGER NOT NULL, ip TEXT NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, PRIMARY KEY (user_id, ip))`,
	// v16: DDNS
	`CREATE TABLE ddns (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, provider TEXT NOT NULL,
		creds TEXT NOT NULL DEFAULT '{}', domain TEXT NOT NULL, rtype TEXT NOT NULL DEFAULT 'A', source TEXT NOT NULL DEFAULT '{}',
		interval_min INTEGER NOT NULL DEFAULT 5, on_change INTEGER NOT NULL DEFAULT 1, ttl INTEGER NOT NULL DEFAULT 300, proxied INTEGER NOT NULL DEFAULT 0,
		last_ip TEXT NOT NULL DEFAULT '', last_ok INTEGER NOT NULL DEFAULT 0, last_run INTEGER NOT NULL DEFAULT 0, last_err TEXT NOT NULL DEFAULT '',
		created INTEGER NOT NULL);
	 CREATE TABLE ddns_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ddns_id INTEGER NOT NULL, ts INTEGER NOT NULL, ip TEXT NOT NULL, ok INTEGER NOT NULL,
		msg TEXT NOT NULL DEFAULT '');
	 CREATE INDEX ddns_log_id ON ddns_log(ddns_id, ts)`,
	// v17: internet and WAN line events (for the dashboard)
	`CREATE TABLE net_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '');
	 CREATE INDEX net_events_ts ON net_events(ts)`,
	// v18: passkeys (WebAuthn credentials, per user and name)
	`CREATE TABLE passkeys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		rp_id TEXT NOT NULL, cred_id TEXT NOT NULL UNIQUE, cred TEXT NOT NULL, name TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER NOT NULL DEFAULT 0);
	 CREATE INDEX passkeys_user ON passkeys(user_id)`,
	// v19: how each user signs in (password | two_step | passkey)
	`ALTER TABLE users ADD COLUMN login_mode TEXT NOT NULL DEFAULT 'password'`,
	// v20: Berth integration (berth.go): the pairing, user mapping, bans, DDNS ownership, nonces
	`CREATE TABLE berth_link (id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, cert_fp TEXT NOT NULL, token_hash TEXT NOT NULL,
		outbound_token_enc TEXT NOT NULL, sign_key_enc TEXT NOT NULL, scopes TEXT NOT NULL, target_devices TEXT NOT NULL, expires_at INTEGER,
		created_at INTEGER NOT NULL, last_seen_at INTEGER, wharf_url TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
		last_error TEXT NOT NULL DEFAULT '');
	 CREATE UNIQUE INDEX berth_link_token ON berth_link(token_hash);
	 CREATE TABLE berth_user_map (berth_user TEXT PRIMARY KEY, wharf_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE);
	 CREATE TABLE berth_bans (id INTEGER PRIMARY KEY, cidr TEXT NOT NULL, reason TEXT, source TEXT, expires_at INTEGER, created_at INTEGER NOT NULL,
		origin TEXT NOT NULL DEFAULT 'berth', sync INTEGER NOT NULL DEFAULT 0, remote_id TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT '');
	 CREATE TABLE ddns_owner (domain TEXT PRIMARY KEY, owner TEXT NOT NULL CHECK (owner IN ('wharf','berth')));
	 CREATE TABLE berth_nonce (nonce TEXT PRIMARY KEY, seen_at INTEGER NOT NULL)`,
	// v21: plugins taken over by Wharf, with their pages converted ahead of time (plugin_import.go)
	`CREATE TABLE plugin_imports (pkg TEXT PRIMARY KEY, version TEXT NOT NULL, imported_at INTEGER NOT NULL, imported_by TEXT NOT NULL,
		pages TEXT NOT NULL, refreshed_at INTEGER NOT NULL DEFAULT 0)`,
}

func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8) // WAL: concurrent readers, writers wait on busy_timeout
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)`); err != nil {
		return nil, err
	}
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(v),0) FROM schema_version`).Scan(&v); err != nil {
		return nil, err
	}
	for i := v; i < len(migrations); i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			return nil, fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_version(v) VALUES(?)`, i+1); err != nil {
			return nil, err
		}
	}
	return db, nil
}
