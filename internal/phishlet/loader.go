package phishlet

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/travisbale/mirage/internal/aitm"
)

// Loader reads phishlet YAML files, validates them, and compiles all regexes.
// The zero value is ready to use.
type Loader struct{}

// Load reads the YAML file at path and returns a fully compiled Phishlet.
// Errors from Load are always ParseErrors.
func (l *Loader) Load(path string) (*aitm.Phishlet, error) {
	raw, err := l.parseFile(path)
	if err != nil {
		return nil, err
	}
	return l.compile(path, raw)
}

// parseFile reads and YAML-decodes a phishlet file into the raw struct.
// KnownFields mode is enabled so typos in field names are caught here.
func (l *Loader) parseFile(path string) (*rawPhishlet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading phishlet file %q: %w", path, err)
	}

	var raw rawPhishlet
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		// YAML decoder errors include line numbers but not field paths.
		// We surface them as a single ParseError on the top-level field.
		return nil, ParseErrors{{
			File:    path,
			Field:   "(yaml)",
			Message: err.Error(),
		}}
	}

	return &raw, nil
}

// compile validates the raw phishlet, compiles all regexes, and constructs the
// aitm.Phishlet. All errors found are collected and returned together as ParseErrors.
func (l *Loader) compile(path string, raw *rawPhishlet) (*aitm.Phishlet, error) {
	var errs ParseErrors

	errs = append(errs, l.validateIdentity(path, raw)...)

	proxyHosts, phErrs := l.compileProxyHosts(path, raw.ProxyHosts)
	errs = append(errs, phErrs...)

	subFilters, sfErrs := l.compileSubFilters(path, raw.SubFilters)
	errs = append(errs, sfErrs...)

	authTokens, atErrs := l.compileAuthTokens(path, raw.AuthTokens)
	errs = append(errs, atErrs...)

	credRules, credErrs := l.compileCredentials(path, raw.Credentials)
	errs = append(errs, credErrs...)

	forcePosts, fpErrs := l.compileForcePosts(path, raw.ForcePosts)
	errs = append(errs, fpErrs...)

	intercepts, intErrs := l.compileIntercepts(path, raw.Intercepts)
	errs = append(errs, intErrs...)

	jsInjects, jsErrs := l.compileJSInjects(path, raw.JSInjects)
	errs = append(errs, jsErrs...)

	if len(errs) > 0 {
		return nil, errs
	}

	return &aitm.Phishlet{
		Name:        raw.Name,
		Author:      raw.Author,
		Version:     raw.Version,
		ProxyHosts:  proxyHosts,
		SubFilters:  subFilters,
		AuthTokens:  authTokens,
		Credentials: credRules,
		Login: aitm.LoginSpec{
			Domain: raw.Login.Domain,
			Path:   raw.Login.Path,
		},
		ForcePosts: forcePosts,
		Intercepts: intercepts,
		JSInjects:  jsInjects,
	}, nil
}

func (l *Loader) validateIdentity(path string, raw *rawPhishlet) ParseErrors {
	var errs ParseErrors
	if raw.Name == "" {
		errs = append(errs, ParseError{File: path, Field: "name", Message: "required"})
	}
	if raw.Author == "" {
		errs = append(errs, ParseError{File: path, Field: "author", Message: "required"})
	}
	if raw.Version == "" {
		errs = append(errs, ParseError{File: path, Field: "version", Message: "required"})
	}
	return errs
}

func (l *Loader) compileProxyHosts(path string, raw []rawProxyHost) ([]aitm.ProxyHost, ParseErrors) {
	var errs ParseErrors
	if len(raw) == 0 {
		errs = append(errs, ParseError{
			File:    path,
			Field:   "proxy_hosts",
			Message: "at least one proxy_host is required",
		})
		return nil, errs
	}
	hosts := make([]aitm.ProxyHost, 0, len(raw))
	for i, rawHost := range raw {
		field := fmt.Sprintf("proxy_hosts[%d]", i)
		if rawHost.PhishSub == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".phish_sub", Message: "required"})
		}
		if rawHost.OrigSub == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".orig_sub", Message: "required"})
		}
		if rawHost.Domain == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".domain", Message: "required"})
		}
		autoFilter := true
		if rawHost.AutoFilter != nil {
			autoFilter = *rawHost.AutoFilter
		}
		hosts = append(hosts, aitm.ProxyHost{
			PhishSubdomain: rawHost.PhishSub,
			OrigSubdomain:  rawHost.OrigSub,
			Domain:         rawHost.Domain,
			IsLanding:      rawHost.IsLanding,
			IsSession:      rawHost.IsSession,
			AutoFilter:     autoFilter,
		})
	}
	return hosts, errs
}

func (l *Loader) compileSubFilters(path string, raw []rawSubFilter) ([]aitm.SubFilter, ParseErrors) {
	var errs ParseErrors
	filters := make([]aitm.SubFilter, 0, len(raw))
	for i, rawFilter := range raw {
		field := fmt.Sprintf("sub_filters[%d]", i)
		if rawFilter.Search == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".search", Message: "required"})
			continue
		}
		searchRegex, err := mustCompile(rawFilter.Search, path, field+".search", &errs)
		if err != nil {
			continue
		}
		filters = append(filters, aitm.SubFilter{
			Hostname:  rawFilter.Hostname,
			MimeTypes: rawFilter.MimeTypes,
			Search:    searchRegex,
			Replace:   rawFilter.Replace,
		})
	}
	return filters, errs
}

func (l *Loader) compileAuthTokens(path string, raw []rawAuthToken) ([]aitm.TokenRule, ParseErrors) {
	var errs ParseErrors
	if len(raw) == 0 {
		errs = append(errs, ParseError{
			File:    path,
			Field:   "auth_tokens",
			Message: "at least one auth_token entry is required",
		})
		return nil, errs
	}
	var rules []aitm.TokenRule
	for i, rawToken := range raw {
		field := fmt.Sprintf("auth_tokens[%d]", i)
		tokenType := aitm.TokenTypeCookie
		switch strings.ToLower(rawToken.Type) {
		case "", "cookie":
			tokenType = aitm.TokenTypeCookie
		case "body":
			tokenType = aitm.TokenTypeBody
		case "header":
			tokenType = aitm.TokenTypeHTTPHeader
		default:
			errs = append(errs, ParseError{
				File:    path,
				Field:   field + ".type",
				Message: fmt.Sprintf("unknown token type %q; must be cookie, body, or header", rawToken.Type),
			})
		}
		if rawToken.Domain == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".domain", Message: "required"})
		}
		for j, key := range rawToken.Keys {
			kField := fmt.Sprintf("%s.keys[%d]", field, j)
			if key.Name == "" {
				errs = append(errs, ParseError{File: path, Field: kField + ".name", Message: "required"})
				continue
			}
			nameRe, err := mustCompile(key.Name, path, kField+".name", &errs)
			if err != nil {
				continue
			}
			var searchRe *regexp.Regexp
			if key.Search != "" {
				searchRe, err = mustCompile(key.Search, path, kField+".search", &errs)
				if err != nil {
					continue
				}
			}
			rules = append(rules, aitm.TokenRule{
				Type:     tokenType,
				Domain:   rawToken.Domain,
				Name:     nameRe,
				Search:   searchRe,
				HTTPOnly: key.HTTPOnly,
				Always:   key.Always,
			})
		}
	}
	return rules, errs
}

// compileCredentials validates and compiles the credentials section.
func (l *Loader) compileCredentials(path string, raw rawCredentials) (aitm.CredentialRules, ParseErrors) {
	var errs ParseErrors

	compileRule := func(field string, r rawCredRule) (aitm.CredentialRule, bool) {
		if r.Key == "" && r.Search == "" {
			// Empty credential rule — skip silently (credentials section is optional).
			return aitm.CredentialRule{}, false
		}
		keyRe, err := regexp.Compile(r.Key)
		if err != nil {
			errs = append(errs, ParseError{
				File:    path,
				Field:   field + ".key",
				Message: fmt.Sprintf("invalid regex: %v", err),
			})
			return aitm.CredentialRule{}, false
		}
		searchRe, err := regexp.Compile(r.Search)
		if err != nil {
			errs = append(errs, ParseError{
				File:    path,
				Field:   field + ".search",
				Message: fmt.Sprintf("invalid regex: %v", err),
			})
			return aitm.CredentialRule{}, false
		}
		credType := r.Type
		if credType == "" {
			credType = "post"
		}
		return aitm.CredentialRule{Key: keyRe, Search: searchRe, Type: credType}, true
	}

	var rules aitm.CredentialRules

	if compiledRule, ok := compileRule("credentials.username", raw.Username); ok {
		rules.Username = compiledRule
	}
	if compiledRule, ok := compileRule("credentials.password", raw.Password); ok {
		rules.Password = compiledRule
	}
	for i, custom := range raw.Custom {
		field := fmt.Sprintf("credentials.custom[%d]", i)
		if custom.Name == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".name", Message: "required"})
			continue
		}
		if compiledRule, ok := compileRule(field, custom.rawCredRule); ok {
			rules.Custom = append(rules.Custom, aitm.CustomCredentialRule{Name: custom.Name, CredentialRule: compiledRule})
		}
	}

	return rules, errs
}

func (l *Loader) compileForcePosts(path string, raw []rawForcePost) ([]aitm.ForcePost, ParseErrors) {
	var errs ParseErrors
	posts := make([]aitm.ForcePost, 0, len(raw))
	for i, rawPost := range raw {
		field := fmt.Sprintf("force_post[%d]", i)
		if rawPost.Path == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".path", Message: "required"})
			continue
		}
		pathRe, err := mustCompile(rawPost.Path, path, field+".path", &errs)
		if err != nil {
			continue
		}
		var conds []aitm.ForcePostCondition
		for j, condition := range rawPost.Conditions {
			cField := fmt.Sprintf("%s.conditions[%d]", field, j)
			keyRe, err := mustCompile(condition.Key, path, cField+".key", &errs)
			if err != nil {
				continue
			}
			searchRe, err := mustCompile(condition.Search, path, cField+".search", &errs)
			if err != nil {
				continue
			}
			conds = append(conds, aitm.ForcePostCondition{Key: keyRe, Search: searchRe})
		}
		var fparams []aitm.ForcePostParam
		for _, param := range rawPost.Params {
			fparams = append(fparams, aitm.ForcePostParam{
				Key:   param.Key,
				Value: param.Value,
			})
		}
		posts = append(posts, aitm.ForcePost{
			Path:       pathRe,
			Conditions: conds,
			Params:     fparams,
		})
	}
	return posts, errs
}

func (l *Loader) compileIntercepts(path string, raw []rawIntercept) ([]aitm.InterceptRule, ParseErrors) {
	var errs ParseErrors
	intercepts := make([]aitm.InterceptRule, 0, len(raw))
	for i, rawIntercept := range raw {
		field := fmt.Sprintf("intercept[%d]", i)
		if rawIntercept.Path == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".path", Message: "required"})
			continue
		}
		pathRe, err := mustCompile(rawIntercept.Path, path, field+".path", &errs)
		if err != nil {
			continue
		}
		var bodyRe *regexp.Regexp
		if rawIntercept.BodySearch != "" {
			bodyRe, err = mustCompile(rawIntercept.BodySearch, path, field+".body_search", &errs)
			if err != nil {
				continue
			}
		}
		if rawIntercept.Status == 0 {
			errs = append(errs, ParseError{File: path, Field: field + ".status", Message: "required"})
		}
		intercepts = append(intercepts, aitm.InterceptRule{
			Path:        pathRe,
			BodySearch:  bodyRe,
			StatusCode:  rawIntercept.Status,
			ContentType: rawIntercept.ContentType,
			Body:        rawIntercept.Body,
		})
	}
	return intercepts, errs
}

func (l *Loader) compileJSInjects(path string, raw []rawJSInject) ([]aitm.JSInject, ParseErrors) {
	var errs ParseErrors
	injects := make([]aitm.JSInject, 0, len(raw))
	for i, rawJSInject := range raw {
		field := fmt.Sprintf("js_inject[%d]", i)
		var triggerPathRe *regexp.Regexp
		if rawJSInject.TriggerPath != "" {
			var err error
			triggerPathRe, err = mustCompile(rawJSInject.TriggerPath, path, field+".trigger_path", &errs)
			if err != nil {
				continue
			}
		}
		injects = append(injects, aitm.JSInject{
			TriggerDomain: rawJSInject.TriggerDomain,
			TriggerPath:   triggerPathRe,
			Script:        rawJSInject.Script,
		})
	}
	return injects, errs
}

// mustCompile compiles pattern as a regex, appending a ParseError to errs on
// failure and returning a non-nil error. On success, err is nil.
func mustCompile(pattern, file, field string, errs *ParseErrors) (*regexp.Regexp, error) {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		*errs = append(*errs, ParseError{
			File:    file,
			Field:   field,
			Message: fmt.Sprintf("invalid regex: %v", err),
		})
		return nil, err
	}
	return compiled, nil
}
