-- Wharf: load a LuCI CBI model with LuCI's own parser and print its form tree as
-- JSON, so the panel can draw the plugin's settings in its own design.
-- Read-only: the model is loaded, never parsed as a submitted form.
--   lua cbidump.lua <model> [lang]
local model, lang = arg[1], arg[2] or "zh_cn"
local jsonc = require "luci.jsonc"
local util = require "luci.util"

local function out(t) io.write(jsonc.stringify(t)) os.exit(0) end

local ok, err = pcall(function()
	local i18n = require "luci.i18n"
	pcall(i18n.setlanguage, lang)
	local http = require "luci.http"
	http.formvalue = function() return nil end
	http.formvaluetable = function() return {} end
	http.getenv = function() return nil end
	http.write = function() end
	local disp = require "luci.dispatcher"
	disp.context = disp.context or {}
	local ctx = disp.context
	ctx.request = ctx.request or { "admin" }
	ctx.requestpath = ctx.requestpath or { "admin" }
	ctx.requestargs = ctx.requestargs or {}
	ctx.path = ctx.path or { "admin" }
	ctx.authsession = ctx.authsession or "00000000000000000000000000000000"
	ctx.authuser = ctx.authuser or "root"
end)

local cbi = require "luci.cbi"
local loaded, maps = pcall(cbi.load, model)
if not loaded then out({ error = tostring(maps) }) end

local classes = { "Flag", "ListValue", "MultiValue", "DynamicList", "StaticList", "DummyValue", "Button", "TextValue",
	"Value", "Table", "TypedSection", "NamedSection", "SimpleSection", "SimpleForm", "Delegator", "Map", "Compound" }
local function cls(o)
	for _, n in ipairs(classes) do
		if cbi[n] and util.instanceof(o, cbi[n]) then return n end
	end
	return "Node"
end

local function str(v)
	if v == nil then return nil end
	if type(v) == "table" then return nil end
	if type(v) == "function" then return nil end
	return tostring(v)
end

local function deps(o)
	local list = {}
	for _, d in ipairs(o.deps or {}) do
		local src = d.deps or d
		local one = {}
		local any = false
		for k, v in pairs(src) do
			if type(k) == "string" and k ~= "add" then
				one[k:gsub("^cbid%.[^.]+%.[^.]+%.", "")] = (type(v) == "boolean") and (v and "1" or "") or tostring(v)
				any = true
			end
		end
		if any then list[#list + 1] = one end
	end
	return list
end

local function custom(o, name)
	return rawget(o, name) ~= nil
end

local function option(o, sections)
	local t = {
		class = cls(o), option = str(o.option), title = str(o.title), description = str(o.description),
		template = str(o.template), datatype = str(o.datatype), default = str(o.default),
		placeholder = str(o.placeholder), rmempty = o.rmempty and true or false, optional = o.optional and true or false,
		password = o.password and true or false, readonly = o.readonly and true or false,
		enabled = str(o.enabled), disabled = str(o.disabled), widget = str(o.widget), delimiter = str(o.delimiter),
		rows = tonumber(o.rows), size = tonumber(o.size), inputtitle = str(o.inputtitle),
		custom_write = custom(o, "write") or custom(o, "remove"), custom_value = custom(o, "cfgvalue"),
		deps = deps(o),
	}
	if type(o.keylist) == "table" and #o.keylist > 0 then
		t.choices = {}
		for i, k in ipairs(o.keylist) do
			t.choices[#t.choices + 1] = { tostring(k), tostring(o.vallist and o.vallist[i] or k) }
		end
	end
	-- values the page would show (custom cfgvalue functions included)
	if t.option and #sections > 0 then
		t.values = {}
		for _, sid in ipairs(sections) do
			local okv, v = pcall(o.cfgvalue, o, sid)
			if okv and v ~= nil then
				if type(v) == "table" then
					local l = {}
					for _, x in ipairs(v) do l[#l + 1] = tostring(x) end
					t.values[sid] = l
				else
					t.values[sid] = tostring(v)
				end
			end
		end
		if next(t.values) == nil then t.values = nil end
	end
	return t
end

local function section(s)
	local t = {
		class = cls(s), sectiontype = str(s.sectiontype), section = str(s.section), title = str(s.title),
		description = str(s.description), template = str(s.template), addremove = s.addremove and true or false,
		anonymous = s.anonymous and true or false, sortable = s.sortable and true or false,
		extedit = type(s.extedit) == "string" and s.extedit or nil, children = {}, tabs = {},
	}
	local sids = {}
	if t.class == "NamedSection" then
		sids = { s.section }
	elseif s.cfgsections then
		local okc, l = pcall(s.cfgsections, s)
		if okc and type(l) == "table" then sids = l end
	end
	t.sections = sids
	local tabOf = {}
	if type(s.tab_names) == "table" then
		for _, name in ipairs(s.tab_names) do
			local tab = s.tabs[name]
			t.tabs[#t.tabs + 1] = { name = name, title = str(tab.title) or name, description = str(tab.description) }
			for _, c in ipairs(tab.childs or {}) do tabOf[c] = name end
		end
	end
	for _, c in ipairs(s.children or {}) do
		local o = option(c, sids)
		o.tab = tabOf[c]
		t.children[#t.children + 1] = o
	end
	return t
end

local function map(m)
	local t = {
		class = cls(m), config = str(m.config), title = str(m.title), description = str(m.description),
		template = str(m.template), children = {}, readonly = m.readonly and true or false,
		submit = m.submit ~= false, pageaction = m.pageaction ~= false,
	}
	for _, s in ipairs(m.children or {}) do
		if util.instanceof(s, cbi.AbstractSection) then
			t.children[#t.children + 1] = section(s)
		else
			local n = option(s, {})
			n.class = cls(s)
			t.children[#t.children + 1] = n
		end
	end
	return t
end

local res = { maps = {} }
for _, m in ipairs(maps) do res.maps[#res.maps + 1] = map(m) end
out(res)
