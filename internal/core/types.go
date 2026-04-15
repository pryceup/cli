// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package core

import (
	"fmt"
	"net/url"
	"strings"
)

// LarkBrand represents the Lark platform brand.
// "feishu" targets China-mainland, "lark" targets international.
// Any other string is treated as a custom base URL.
type LarkBrand string

const (
	BrandFeishu LarkBrand = "feishu"
	BrandLark   LarkBrand = "lark"
)

// ParseBrand normalizes a brand string to a LarkBrand constant.
// Unrecognized values default to BrandFeishu.
func ParseBrand(value string) LarkBrand {
	if value == "lark" {
		return BrandLark
	}
	return BrandFeishu
}

// Endpoints holds resolved endpoint URLs for different Lark services.
type Endpoints struct {
	Open     string `json:"open,omitempty"`     // e.g. "https://open.feishu.cn"
	Accounts string `json:"accounts,omitempty"` // e.g. "https://accounts.feishu.cn"
	MCP      string `json:"mcp,omitempty"`      // e.g. "https://mcp.feishu.cn"
}

// ResolveEndpoints resolves endpoint URLs based on brand.
func ResolveEndpoints(brand LarkBrand) Endpoints {
	switch brand {
	case BrandLark:
		return Endpoints{
			Open:     "https://open.larksuite.com",
			Accounts: "https://accounts.larksuite.com",
			MCP:      "https://mcp.larksuite.com",
		}
	default:
		return Endpoints{
			Open:     "https://open.feishu.cn",
			Accounts: "https://accounts.feishu.cn",
			MCP:      "https://mcp.feishu.cn",
		}
	}
}

// ResolveOpenBaseURL returns the Open API base URL for the given brand.
func ResolveOpenBaseURL(brand LarkBrand) string {
	return ResolveEndpoints(brand).Open
}

// ResolveEndpointsWithOverride resolves endpoint URLs using brand defaults,
// then applies any non-empty fields from override.
func ResolveEndpointsWithOverride(brand LarkBrand, override *Endpoints) Endpoints {
	ep := ResolveEndpoints(brand)
	if override == nil {
		return ep
	}
	if override.Open != "" {
		ep.Open = strings.TrimRight(override.Open, "/")
	}
	if override.Accounts != "" {
		ep.Accounts = strings.TrimRight(override.Accounts, "/")
	}
	if override.MCP != "" {
		ep.MCP = strings.TrimRight(override.MCP, "/")
	}
	return ep
}

// ValidateEndpointURL checks that a URL is a valid HTTPS endpoint URL.
func ValidateEndpointURL(u string) error {
	if u == "" {
		return nil // empty is valid (means use default)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", u, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("endpoint URL %q must use HTTPS", u)
	}
	if parsed.Host == "" {
		return fmt.Errorf("endpoint URL %q missing host", u)
	}
	return nil
}
