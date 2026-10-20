package rules

// Extra services maintained here because blackmatrix7 has no list for them (or
// bundles them into a broader one). They are compiled before Catalog, so they win
// over broader lists that contain the same domains.
type Extra struct {
	Name, Category, Sub, Company string
	Domains                      []string // domain suffixes
}

var Extras = []Extra{
	// AI — chat assistants
	{"ChatGPT", "AI", "聊天助手", "OpenAI", []string{"chatgpt.com", "chat.openai.com", "oaistatic.com", "oaiusercontent.com", "sora.com"}},
	{"OpenAI API", "AI", "模型平台", "OpenAI", []string{"api.openai.com", "platform.openai.com"}},
	{"Claude", "AI", "聊天助手", "Anthropic", []string{"claude.ai", "claude.com", "claudeusercontent.com"}},
	{"Anthropic API", "AI", "模型平台", "Anthropic", []string{"api.anthropic.com", "console.anthropic.com"}},
	{"Gemini", "AI", "聊天助手", "Google", []string{"gemini.google.com", "bard.google.com", "aistudio.google.com", "generativelanguage.googleapis.com", "notebooklm.google.com"}},
	{"Grok", "AI", "聊天助手", "xAI", []string{"grok.com", "x.ai", "grok.x.com"}},
	{"Microsoft Copilot", "AI", "聊天助手", "Microsoft", []string{"copilot.microsoft.com", "sydney.bing.com", "copilot.cloud.microsoft"}},
	{"Perplexity", "AI", "聊天助手", "Perplexity", []string{"perplexity.ai", "pplx.ai"}},
	{"Poe", "AI", "聊天助手", "Quora", []string{"poe.com", "poecdn.net"}},
	{"Character.AI", "AI", "聊天助手", "Character.AI", []string{"character.ai", "c.ai"}},
	{"Meta AI", "AI", "聊天助手", "Meta", []string{"meta.ai"}},
	{"Mistral", "AI", "聊天助手", "Mistral AI", []string{"mistral.ai"}},
	{"DeepSeek", "AI", "聊天助手", "深度求索", []string{"deepseek.com"}},
	{"Kimi", "AI", "聊天助手", "月之暗面", []string{"kimi.com", "kimi.moonshot.cn", "moonshot.cn"}},
	{"豆包", "AI", "聊天助手", "字节跳动", []string{"doubao.com", "doubao.cn"}},
	{"通义千问", "AI", "聊天助手", "阿里巴巴", []string{"tongyi.aliyun.com", "qianwen.aliyun.com", "tongyi.com"}},
	{"文心一言", "AI", "聊天助手", "百度", []string{"yiyan.baidu.com", "ernie.baidu.com"}},
	{"腾讯元宝", "AI", "聊天助手", "腾讯", []string{"yuanbao.tencent.com"}},
	{"智谱清言", "AI", "聊天助手", "智谱", []string{"chatglm.cn", "bigmodel.cn", "zhipuai.cn"}},
	{"MiniMax", "AI", "聊天助手", "MiniMax", []string{"minimax.io", "minimaxi.com", "hailuoai.com"}},
	// AI — coding
	{"GitHub Copilot", "AI", "编程助手", "Microsoft", []string{"githubcopilot.com", "copilot-proxy.githubusercontent.com"}},
	{"Cursor", "AI", "编程助手", "Anysphere", []string{"cursor.com", "cursor.sh", "cursorapi.com"}},
	{"Windsurf", "AI", "编程助手", "Windsurf", []string{"windsurf.com", "codeium.com"}},
	// AI — image / media / platforms
	{"Midjourney", "AI", "绘图与多媒体", "Midjourney", []string{"midjourney.com"}},
	{"Runway", "AI", "绘图与多媒体", "Runway", []string{"runwayml.com"}},
	{"Suno", "AI", "绘图与多媒体", "Suno", []string{"suno.com", "suno.ai"}},
	{"ElevenLabs", "AI", "绘图与多媒体", "ElevenLabs", []string{"elevenlabs.io"}},
	{"Hugging Face", "AI", "模型平台", "Hugging Face", []string{"huggingface.co", "hf.co"}},
	{"Replicate", "AI", "模型平台", "Replicate", []string{"replicate.com", "replicate.delivery"}},
	{"OpenRouter", "AI", "模型平台", "OpenRouter", []string{"openrouter.ai"}},
	// video / social not covered upstream
	{"Bluesky", "社交", "社交网络", "Bluesky", []string{"bsky.app", "bsky.social", "bsky.network"}},
	{"Mastodon", "社交", "社交网络", "Mastodon", []string{"mastodon.social", "joinmastodon.org"}},
	{"Signal", "即时通讯", "聊天", "Signal", []string{"signal.org", "whispersystems.org"}},
	{"Zoom", "办公协作", "视频会议", "Zoom", []string{"zoom.us", "zoom.com", "zoomgov.com"}},
	{"Ring", "智能家居", "摄像头与安防", "Amazon", []string{"ring.com", "ring.devices.a2z.com"}},
	{"小米摄像头", "智能家居", "摄像头与安防", "小米", []string{"camera.io.mi.com", "business.smartcamera.api.io.mi.com"}},
	{"Tuya 涂鸦", "智能家居", "IoT 平台", "涂鸦", []string{"tuyaus.com", "tuyaeu.com", "tuyacn.com", "tuya.com"}},
	{"三星 SmartThings", "智能家居", "IoT 平台", "Samsung", []string{"smartthings.com"}},
	{"NextDNS", "系统与更新", "网络服务", "NextDNS", []string{"nextdns.io"}},
}

// Sub-categories for Catalog entries (by list name); entries not listed use their category.
var Subs = map[string]string{
	// video
	"YouTube": "视频平台", "Netflix": "流媒体", "Disney": "流媒体", "PrimeVideo": "流媒体", "HBO": "流媒体", "Hulu": "流媒体",
	"AppleTV": "流媒体", "Peacock": "流媒体", "ParamountPlus": "流媒体", "DAZN": "体育直播", "Emby": "私有影音",
	"iQIYI": "长视频", "iQIYIIntl": "长视频", "TencentVideo": "长视频", "WeTV": "长视频", "Youku": "长视频", "HunanTV": "长视频",
	"BiliBili": "视频平台", "BiliBiliIntl": "视频平台", "AcFun": "视频平台", "Vimeo": "视频平台", "Dailymotion": "视频平台", "Niconico": "视频平台",
	"DouYin": "短视频", "TikTok": "短视频", "KuaiShou": "短视频",
	"Twitch": "直播", "Douyu": "直播", "HuYa": "直播",
	"CCTV": "电视台", "Migu": "电视台", "TVB": "电视台", "ViuTV": "电视台", "Abema": "电视台",
	// music
	"Spotify": "音乐流媒体", "AppleMusic": "音乐流媒体", "YouTubeMusic": "音乐流媒体", "NetEaseMusic": "音乐流媒体", "KugouKuwo": "音乐流媒体",
	"TIDAL": "音乐流媒体", "Deezer": "音乐流媒体", "KKBOX": "音乐流媒体", "JOOX": "音乐流媒体", "SoundCloud": "音乐流媒体",
	"Himalaya": "播客与有声", "Pandora": "电台", "LastFM": "音乐社区",
	// social
	"Facebook": "社交网络", "Instagram": "图片社交", "Threads": "社交网络", "Twitter": "社交网络", "Snap": "图片社交", "VK": "社交网络",
	"Weibo": "社交网络", "XiaoHongShu": "生活种草", "Pinterest": "图片社交", "Pixiv": "图片社交", "Tumblr": "社交网络",
	"Reddit": "社区论坛", "Zhihu": "社区论坛", "DouBan": "社区论坛", "BaiDuTieBa": "社区论坛", "Hupu": "社区论坛", "LinkedIn": "职场社交",
	"Clubhouse": "语音社交", "Tencent": "综合", "ByteDance": "综合",
	// messaging
	"WeChat": "聊天", "Telegram": "聊天", "Whatsapp": "聊天", "Line": "聊天", "KakaoTalk": "聊天", "Zalo": "聊天", "Discord": "社群",
	// news
	"BBC": "新闻", "CNN": "新闻", "NYTimes": "新闻", "Bloomberg": "财经新闻", "ThomsonReuters": "新闻", "Nikkei": "财经新闻",
	"AppleNews": "新闻聚合", "FlipBoard": "新闻聚合", "Sina": "门户", "Sohu": "门户", "FengHuangWang": "门户", "NetEase": "门户",
	"36kr": "科技", "Wikipedia": "百科", "Wikimedia": "百科",
	// office
	"Teams": "视频会议", "Notion": "文档协作", "Slack": "团队沟通", "DingTalk": "团队沟通", "Figma": "设计",
	"Adobe": "设计", "Atlassian": "项目管理", "Teambition": "项目管理", "Zoho": "办公套件", "Kingsoft": "办公套件",
	"Salesforce": "企业软件", "TeamViewer": "远程控制", "RemoteDesktop": "远程控制", "Mail": "邮件",
	// AI (upstream lists)
	"OpenAI": "聊天助手", "Claude": "聊天助手", "Anthropic": "模型平台", "Gemini": "聊天助手", "Copilot": "聊天助手", "Civitai": "绘图与多媒体",
	// dev
	"GitHub": "代码托管", "GitLab": "代码托管", "Gitee": "代码托管", "Docker": "开发工具", "Npmjs": "包管理", "Python": "包管理",
	"Jetbrains": "开发工具", "Stackexchange": "开发社区", "CSDN": "开发社区", "JueJin": "开发社区", "Vercel": "部署平台",
	"Heroku": "部署平台", "HashiCorp": "开发工具", "AppleDev": "开发工具",
	// shopping
	"Amazon": "综合电商", "eBay": "综合电商", "JingDong": "综合电商", "Pinduoduo": "综合电商", "Alibaba": "综合电商", "Shopee": "综合电商",
	"XianYu": "二手", "SMZDM": "导购", "VipShop": "特卖", "Shopify": "店铺平台", "IKEA": "品牌", "Nike": "品牌",
	// finance
	"PayPal": "支付", "AliPay": "支付", "Stripe": "支付", "UnionPay": "支付", "VISA": "支付",
	"Binance": "加密货币", "OKX": "加密货币", "Cryptocurrency": "加密货币",
	"EastMoney": "证券理财", "XueQiu": "证券理财", "TigerFintech": "证券理财", "CMB": "银行", "ICBC": "银行",
	// games
	"Steam": "游戏平台", "SteamCN": "游戏平台", "Epic": "游戏平台", "Gog": "游戏平台", "TapTap": "游戏平台",
	"PlayStation": "主机", "Nintendo": "主机", "Xbox": "主机",
	"Blizzard": "游戏厂商", "Riot": "游戏厂商", "EA": "游戏厂商", "Ubisoft": "游戏厂商", "Rockstar": "游戏厂商", "Supercell": "游戏厂商",
	"HoYoverse": "游戏厂商", "Garena": "游戏厂商", "Majsoul": "游戏厂商", "4399": "小游戏",
	// life
	"MeiTuan": "外卖", "Eleme": "外卖", "DiDi": "打车", "GaoDe": "地图", "XieCheng": "旅行", "FeiZhu": "旅行", "12306": "旅行",
	"Starbucks": "餐饮", "McDonalds": "餐饮", "Accuweather": "天气", "SFExpress": "快递", "KuaiDi100": "快递", "Tesla": "汽车",
	// education
	"Duolingo": "语言学习", "CNKI": "学术", "Scholar": "学术", "Udacity": "在线课程",
	// storage
	"Dropbox": "网盘", "MEGA": "网盘", "PikPak": "网盘", "TeraBox": "网盘", "LanZouYun": "网盘", "JianGuoYun": "网盘",
	"OneDrive": "网盘", "GoogleDrive": "网盘", "iCloud": "网盘", "Xunlei": "下载", "PrivateTracker": "下载",
	"Synology": "NAS", "QuickConnect": "NAS",
	// devices
	"XiaoMi": "手机与 IoT", "Huawei": "手机与 IoT", "Samsung": "家电", "LG": "家电", "Sony": "家电", "TCL": "家电",
	"OPPO": "手机", "Vivo": "手机", "OnePlus": "手机", "MeiZu": "手机", "Lenovo": "电脑", "Logitech": "外设",
	"Chromecast": "投屏", "Hpplay": "投屏",
	// system
	"AppStore": "应用商店", "TestFlight": "应用商店", "SystemOTA": "系统更新", "AppleFirmware": "系统更新",
	"Apple": "系统服务", "Microsoft": "系统服务", "Google": "系统服务", "Android": "系统服务", "MicrosoftEdge": "浏览器", "Mozilla": "浏览器",
	"GoogleFCM": "消息推送", "iCloudPrivateRelay": "隐私代理", "FindMy": "系统服务", "AppleID": "账号", "Siri": "语音助手",
	"Nvidia": "驱动与硬件", "Intel": "驱动与硬件", "AMD": "驱动与硬件", "Ubuntu": "系统更新",
	"NTPService": "网络服务", "Speedtest": "网络服务", "STUN": "网络服务", "DNS": "网络服务",
	// infra
	"Cloudflare": "CDN", "Akamai": "CDN", "Limelight": "CDN", "Jsdelivr": "CDN", "WangSuKeJi": "CDN", "BaiShanYunKeJi": "CDN",
	"QiNiuYun": "云服务", "UPYun": "云服务", "UCloud": "云服务", "DigitalOcean": "云服务", "Oracle": "云服务", "IBM": "云服务",
	"AdvertisingLite": "广告", "EasyPrivacy": "追踪统计",
	// search
	"GoogleSearch": "搜索引擎", "Bing": "搜索引擎", "Baidu": "搜索引擎", "Duckduckgo": "搜索引擎", "Yandex": "搜索引擎", "ShenMa": "搜索引擎",
}
