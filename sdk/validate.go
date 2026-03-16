package sdk

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"time"
)

// Validate returns a non-nil error if the request contains invalid fields.

func (r CreateLureRequest) Validate() error {
	if r.Phishlet == "" {
		return fmt.Errorf("phishlet: required")
	}
	if r.UAFilter != "" {
		if _, err := regexp.Compile(r.UAFilter); err != nil {
			return fmt.Errorf("ua_filter: invalid regex: %w", err)
		}
	}
	if err := validateURL("redirect_url", r.RedirectURL); err != nil {
		return err
	}
	return validateURL("spoof_url", r.SpoofURL)
}

func (r UpdateLureRequest) Validate() error {
	if r.UAFilter != nil {
		if _, err := regexp.Compile(*r.UAFilter); err != nil {
			return fmt.Errorf("ua_filter: invalid regex: %w", err)
		}
	}
	if r.RedirectURL != nil {
		if err := validateURL("redirect_url", *r.RedirectURL); err != nil {
			return err
		}
	}
	if r.SpoofURL != nil {
		return validateURL("spoof_url", *r.SpoofURL)
	}
	return nil
}

func (r PauseLureRequest) Validate() error {
	if _, err := time.ParseDuration(r.Duration); err != nil {
		return fmt.Errorf("duration: invalid Go duration string")
	}
	return nil
}

func (r AddBotSignatureRequest) Validate() error {
	if r.JA4Hash == "" {
		return fmt.Errorf("ja4_hash: required")
	}
	return nil
}

func (r UpdateBotThresholdRequest) Validate() error {
	if r.Threshold < 0.0 || r.Threshold > 1.0 {
		return fmt.Errorf("threshold: must be between 0.0 and 1.0")
	}
	return nil
}

func (r CreateSubPhishletRequest) Validate() error {
	if r.ParentName == "" {
		return fmt.Errorf("parent_name: required")
	}
	if r.Name == "" {
		return fmt.Errorf("name: required")
	}
	return nil
}

func (r AddBlacklistEntryRequest) Validate() error {
	if r.Value == "" {
		return fmt.Errorf("value: required")
	}
	if net.ParseIP(r.Value) == nil {
		if _, _, err := net.ParseCIDR(r.Value); err != nil {
			return fmt.Errorf("value: must be a valid IP or CIDR")
		}
	}
	return nil
}

// validateURL returns an error if s is non-empty but not a valid absolute HTTP/HTTPS URL.
func validateURL(field, s string) error {
	if s == "" {
		return nil
	}
	u, err := url.ParseRequestURI(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s: must be an absolute http or https URL", field)
	}
	return nil
}
