'use strict';
'require view';
'require form';
'require rpc';
'require uci';
'require ui';
'require poll';

var callStatus = rpc.declare({ object: 'luci.owp', method: 'status', expect: { '': {} } });
var callGenkey = rpc.declare({ object: 'luci.owp', method: 'genkey', expect: { '': {} } });
var callResetSuper = rpc.declare({ object: 'luci.owp', method: 'reset_super', expect: { '': {} } });
var callResetAccess = rpc.declare({ object: 'luci.owp', method: 'reset_access', expect: { '': {} } });
var callClearInitial = rpc.declare({ object: 'luci.owp', method: 'clear_initial', expect: { '': {} } });

function dot(on) {
	return E('span', {
		'style': 'display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:' + (on ? '#2ecc71' : '#bbb')
	});
}

function panelURL() {
	var port = uci.get('owp', 'panel', 'port') || '7080';
	var tls = uci.get('owp', 'panel', 'tls') || 'auto';
	return (tls === 'off' ? 'http' : 'https') + '://' + window.location.hostname + ':' + port + '/';
}

function copyable(value) {
	return E('code', { 'style': 'user-select:all;word-break:break-all' }, value || '-');
}

return view.extend({
	load: function() {
		return Promise.all([callStatus(), uci.load('owp')]);
	},

	renderStatus: function(st) {
		var rows = [
			[_('Agent'), E('span', {}, [dot(st.agent_running), st.agent_running ? _('运行中') : _('已停止')])],
			[_('面板'), E('span', {}, [dot(st.panel_running), st.panel_running ? _('运行中') : _('已停止')])],
			[_('版本'), st.version || '-'],
			[_('数据目录'), (st.data_dir || '-') + (st.data_usage ? '（已用 ' + st.data_usage + '）' : '')],
			[_('访问地址'), E('span', {}, [
				'LAN ', copyable((st.lan_ip || window.location.hostname) + ':' + (uci.get('owp', 'panel', 'port') || '7080')),
				st.wan_ip ? E('span', {}, ['　WAN ', copyable(st.wan_ip + ':' + (uci.get('owp', 'panel', 'port') || '7080'))]) : ''
			])]
		];
		if (st.agent_fingerprint)
			rows.push([_('Agent 证书指纹'), copyable(st.agent_fingerprint)]);

		var table = E('table', { 'class': 'table' }, rows.map(function(r) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'style': 'width:160px' }, r[0]),
				E('td', { 'class': 'td left' }, r[1])
			]);
		}));

		var nodes = [table, E('div', { 'style': 'margin-top:12px' }, [
			E('button', {
				'class': 'btn cbi-button cbi-button-action',
				'disabled': st.panel_running ? null : '',
				'click': function() { window.open(panelURL(), '_blank', 'noopener'); }
			}, _('打开面板')),
			' ',
			E('button', {
				'class': 'btn cbi-button cbi-button-reset',
				'click': ui.createHandlerFn(this, function() {
					if (!confirm(_('确定重置超级管理员密码？所有已登录的超级管理员会话将失效。')))
						return;
					return callResetSuper().then(function(r) {
						if (!r.ok) return ui.addNotification(null, E('p', _('重置失败：面板服务未运行或配置不存在')), 'danger');
						ui.showModal(_('新的超级管理员密码'), [
							E('p', {}, [_('请立即登录面板修改密码：'), copyable(r.password)]),
							E('div', { 'class': 'right' }, E('button', { 'class': 'btn', 'click': function() { ui.hideModal(); location.reload(); } }, _('关闭')))
						]);
					});
				})
			}, _('重置超级管理员密码')),
			' ',
			E('button', {
				'class': 'btn cbi-button cbi-button-reset',
				'title': _('被面板的访问控制挡在外面时使用：放开内网与公网限制、清空 IP 黑名单'),
				'click': ui.createHandlerFn(this, function() {
					if (!confirm(_('确定重置面板访问控制？内网与公网限制将全部放开，IP 黑名单清空。')))
						return;
					return callResetAccess().then(function(r) {
						ui.addNotification(null, E('p', r.ok ? _('访问控制已重置，现在可以重新打开面板') : _('重置失败：面板配置不存在')), r.ok ? 'info' : 'danger');
					});
				})
			}, _('重置面板访问控制'))
		])];

		if (st.initial_password) {
			nodes.unshift(E('div', { 'class': 'alert-message warning', 'style': 'margin-bottom:12px' }, [
				E('strong', {}, _('首次登录')), E('br'),
				_('超级管理员用户名：'), copyable(st.initial_user), '　', _('初始密码：'), copyable(st.initial_password),
				E('br'), _('登录面板修改密码后，此提示会自动消失。'), ' ',
				E('a', { 'href': '#', 'click': ui.createHandlerFn(this, function(ev) {
					ev.preventDefault();
					return callClearInitial().then(function() { location.reload(); });
				}) }, _('我已记下，隐藏'))
			]));
		}
		return E('div', { 'class': 'cbi-section' }, [E('h3', {}, _('运行状态'))].concat(nodes));
	},

	render: function(data) {
		var st = data[0];
		var m, s, o;

		m = new form.Map('owp', _('Wharf 码头'),
			_('Wharf：多管理员的 OpenWrt 控制面板。Agent 负责读写路由器配置；面板提供用户管理、权限、审计与访问记录。面板也可以部署在 VPS 上，通过 Agent 密钥远程管理本路由器。'));

		s = m.section(form.NamedSection, 'panel', 'panel', _('本机面板'));
		o = s.option(form.Flag, 'enabled', _('启用本机面板'), _('VPS 模式下可关闭，只保留 Agent'));
		o.rmempty = false;
		o = s.option(form.Value, 'port', _('端口'));
		o.datatype = 'port';
		o.placeholder = '7080';
		o = s.option(form.ListValue, 'tls', _('HTTPS'));
		o.value('auto', _('自签名证书（推荐）'));
		o.value('off', _('关闭（仅在前面有 HTTPS 反向代理时使用）'));
		o = s.option(form.Flag, 'open_wan', _('允许从 WAN 访问'), _('自动在防火墙放行面板端口'));
		o = s.option(form.DynamicList, 'trusted_proxies', _('可信反向代理'),
			_('面板在反代 / CDN 后面时，填写反代的 IP 或网段，才会采用 X-Forwarded-For / CF-Connecting-IP 作为访问者真实 IP'));
		o.datatype = 'cidr';

		s = m.section(form.NamedSection, 'agent', 'agent', _('Agent'),
			_('VPS 模式：把监听地址改为 0.0.0.0:7071，开启 HTTPS，并在「允许的来源」中填写 VPS 的 IP；然后把下面的 Key ID、密钥和证书指纹填入 VPS 面板的配置。'));
		o = s.option(form.Flag, 'enabled', _('启用 Agent'));
		o.rmempty = false;
		o = s.option(form.Value, 'listen', _('监听地址'));
		o.placeholder = '127.0.0.1:7071';
		o = s.option(form.Flag, 'tls', _('HTTPS'), _('远程连接时必须开启；面板通过证书指纹校验 Agent'));
		o = s.option(form.DynamicList, 'allow_from', _('允许的来源'), _('留空 = 不限制（仅建议在只监听 127.0.0.1 时留空）'));
		o.datatype = 'or(ipaddr,cidr)';
		o = s.option(form.Flag, 'open_wan', _('在 WAN 放行 Agent 端口'), _('仅对「允许的来源」放行'));
		o = s.option(form.DummyValue, 'key_id', _('Key ID'));
		o.cfgvalue = function() { return uci.get('owp', 'agent', 'key_id') || '-'; };
		o = s.option(form.Value, 'secret', _('密钥'));
		o.password = true;
		o.readonly = true;
		o = s.option(form.Button, '_genkey', _('重新生成密钥'));
		o.inputtitle = _('生成新密钥');
		o.inputstyle = 'reset';
		o.onclick = function() {
			if (!confirm(_('生成新密钥后，所有使用旧密钥的远程面板将无法连接（本机面板自动更新）。继续？')))
				return;
			return callGenkey().then(function(r) {
				ui.showModal(_('新的 Agent 密钥'), [
					E('p', {}, [_('Key ID：'), copyable(r.key_id)]),
					E('p', {}, [_('密钥：'), copyable(r.secret)]),
					E('div', { 'class': 'right' }, E('button', { 'class': 'btn', 'click': function() { ui.hideModal(); location.reload(); } }, _('关闭')))
				]);
			});
		};

		s = m.section(form.NamedSection, 'main', 'main', _('存储'));
		o = s.option(form.Value, 'data_dir', _('数据目录'), _('数据库、日志、IP 离线库存放位置；日志较多时建议放在独立分区'));
		o.placeholder = '/etc/owp';

		var statusNode = E('div', {}, this.renderStatus(st));
		poll.add(L.bind(function() {
			return callStatus().then(L.bind(function(s2) {
				var fresh = this.renderStatus(s2);
				statusNode.replaceChildren(fresh);
			}, this));
		}, this), 10);

		return m.render().then(function(formNode) {
			return E('div', {}, [statusNode, formNode]);
		});
	}
});
