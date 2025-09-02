package main

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type Cookie struct {
	Name     string
	Value    string
	Expires  time.Time
	Path     string
	Domain   string
	HttpOnly bool
	Secure   bool
	SameSite string
}

// Anti-Signature #69: Enhanced browser fingerprint structure
type BrowserFingerprint struct {
	UserAgent        string
	AcceptLanguage   string
	AcceptEncoding   string
	Viewport         string
	Timezone         string
	Platform         string
	CookiesEnabled   bool
	DoNotTrack       bool
	ConnectionType   string
	ScreenResolution string
}


func RandomInt(min, max int) int {
	return rand.Intn(max-min+1) + min
}

func RandomElement(elements []string) string {
	return elements[rand.Intn(len(elements))]
}

// Anti-Signature #69: Generate more natural-looking random strings
func RandomString(length int) string {
	// Use different character sets for different contexts to avoid patterns
	charsets := []string{
		"abcdefghijklmnopqrstuvwxyz0123456789",           // lowercase + numbers (common)
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",           // uppercase + numbers
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", // mixed case
		"0123456789abcdef",                               // hex-like
	}
	charset := charsets[rand.Intn(len(charsets))]
	
	var sb strings.Builder
	for i := 0; i < length; i++ {
		sb.WriteByte(charset[rand.Intn(len(charset))])
	}
	return sb.String()
}

// Anti-Signature #37: Generate realistic session IDs that look like standard web applications
func GenerateRealisticSessionID() string {
	patterns := []func() string{
		// Standard alphanumeric session (most common)
		func() string {
			// Use only alphanumeric characters to avoid suspicious patterns
			const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			var sb strings.Builder
			for i := 0; i < 32; i++ {
				sb.WriteByte(charset[rand.Intn(len(charset))])
			}
			return sb.String()
		},
		// Simple hex token (PHP/ASP.NET style)
		func() string {
			const hexChars = "0123456789abcdef"
			var sb strings.Builder
			for i := 0; i < 32; i++ {
				sb.WriteByte(hexChars[rand.Intn(len(hexChars))])
			}
			return sb.String()
		},
		// Standard web session format
		func() string {
			const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
			var sb strings.Builder
			for i := 0; i < 24; i++ {
				sb.WriteByte(charset[rand.Intn(len(charset))])
			}
			return sb.String()
		},
	}
	pattern := patterns[rand.Intn(len(patterns))]
	return pattern()
}

// Anti-Signature #37: Generate standard cache-busting parameters (avoid unusual patterns)
func GenerateCacheBuster(key string) string {
	// Validate key doesn't contain suspicious characters
	if strings.ContainsAny(key, "<>\"';&=#") {
		key = "t" // Use safe default
	}
	
	// Use only standard cache-busting strategies
	strategies := []func(string) string{
		// Unix timestamp (most common and legitimate)
		func(k string) string {
			return fmt.Sprintf("%s=%d", k, time.Now().Unix())
		},
		// Version number (common for assets)
		func(k string) string {
			return fmt.Sprintf("%s=%d", k, rand.Intn(999)+1)
		},
		// Simple number (common for pagination/versions)
		func(k string) string {
			return fmt.Sprintf("%s=%d", k, rand.Intn(9999)+1)
		},
	}
	strategy := strategies[rand.Intn(len(strategies))]
	return strategy(key)
}

// Anti-Signature #37: Generate only standard header values (removed custom x-* headers)
// This function is kept for backward compatibility but returns standard values only
func GenerateNaturalHeaderValue(headerName string) string {
	// Only generate values for standard headers
	switch strings.ToLower(headerName) {
	case "sessionid", "jsessionid", "phpsessid", "aspsessionid":
		return GenerateRealisticSessionID()
	default:
		return RandomString(16) // Fallback for any remaining usage
	}
}

func ParseCookies(raw_cookies []string) ([]Cookie, error) {
	var cookies []Cookie

	for _, raw_cookie := range raw_cookies {
		cookie := Cookie{}
		parts := strings.Split(raw_cookie, ";")

		name_value := strings.Split(parts[0], "=")
		if len(name_value) == 2 {
			cookie.Name = name_value[0]
			cookie.Value = name_value[1]
		}

		for _, part := range parts[1:] {
			part = strings.TrimSpace(part)
			// fmt.Printf("part: %s\n", part)
			switch {
			case strings.HasPrefix(part, "Expires="):
				expiryStr := strings.TrimPrefix(part, "Expires=")
				expiryTime, err := ParseExpiry(expiryStr)
				if err != nil {
					// fmt.Println("error parsing cookie:", err)
					return cookies, fmt.Errorf("invalid expiry date format: %s", err.Error())
				}
				cookie.Expires = expiryTime
				// cookie.Expires = strings.TrimPrefix(part, "Expires=")
			case strings.HasPrefix(part, "Path="):
				cookie.Path = strings.TrimPrefix(part, "Path=")
			case strings.HasPrefix(part, "Domain="):
				cookie.Domain = strings.TrimPrefix(part, "Domain=")
			case strings.EqualFold(part, "HttpOnly"):
				cookie.HttpOnly = true
			}
		}

		cookies = append(cookies, cookie)
	}

	return cookies, nil
}

func FormatCookies(cookies []Cookie) string {
	var cookieHeader string
	for _, cookie := range cookies {
		if cookieHeader != "" {
			cookieHeader += "; "
		}
		cookieHeader += fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
	}

	return cookieHeader
}

func ParseExpiry(expiry string) (time.Time, error) {
	expiry_time, err := time.Parse(time.RFC1123, expiry)
	if err == nil {
		return expiry_time, nil
	}

	expiry = strings.Replace(expiry, "-", " ", -1)
	// fmt.Printf("expiry: %s\n", expiry)
	expiry_time, err = time.Parse(time.RFC1123, expiry)
	if err != nil {
		return time.Time{}, err
	}

	return expiry_time, nil
}

func UpdateCookies(initial_cookies map[string]Cookie, new_cookies []Cookie) map[string]Cookie {
	for _, new_cookie := range new_cookies {
		if existingCookie, exists := initial_cookies[new_cookie.Name]; exists {
			if new_cookie.Expires.After(existingCookie.Expires) {
				initial_cookies[new_cookie.Name] = new_cookie
			}
		} else {
			initial_cookies[new_cookie.Name] = new_cookie
		}
	}

	return initial_cookies
}

// Anti-Signature #37: Generate standard browser cookie values (avoid suspicious patterns)
func GenerateRealisticCookieValue(cookieName string) string {
	// Ensure cookie name doesn't contain suspicious characters
	if strings.ContainsAny(cookieName, "<>\"';&=") {
		return "" // Return empty if suspicious
	}
	
	switch strings.ToLower(cookieName) {
	case "jsessionid":
		// Standard Java session ID pattern (alphanumeric only)
		const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		var sb strings.Builder
		for i := 0; i < 32; i++ {
			sb.WriteByte(charset[rand.Intn(len(charset))])
		}
		return sb.String()
	case "phpsessid":
		// Standard PHP session ID pattern (lowercase alphanumeric)
		const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
		var sb strings.Builder
		for i := 0; i < 26; i++ {
			sb.WriteByte(charset[rand.Intn(len(charset))])
		}
		return sb.String()
	case "asp.net_sessionid":
		// ASP.NET session ID pattern
		const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
		var sb strings.Builder
		for i := 0; i < 24; i++ {
			sb.WriteByte(charset[rand.Intn(len(charset))])
		}
		return sb.String()
	case "_csrf", "csrf_token", "_token":
		// Standard CSRF token
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		var sb strings.Builder
		for i := 0; i < 32; i++ {
			sb.WriteByte(charset[rand.Intn(len(charset))])
		}
		return sb.String()
	case "_ga":
		// Google Analytics (standard format)
		return fmt.Sprintf("GA1.2.%d.%d", rand.Int63n(999999999), time.Now().Unix()-rand.Int63n(86400*7))
	case "_gid":
		// Google Analytics ID (24-hour)
		return fmt.Sprintf("GA1.2.%d.%d", rand.Int63n(999999999), time.Now().Unix()-rand.Int63n(86400))
	case "session_id", "sessionid":
		return GenerateRealisticSessionID()
	default:
		// Standard generic cookie value (alphanumeric only)
		const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
		var sb strings.Builder
		for i := 0; i < 20; i++ {
			sb.WriteByte(charset[rand.Intn(len(charset))])
		}
		return sb.String()
	}
}

// Generate timing variations that look human-like
func GenerateHumanTiming(baseMs int, profile int) time.Duration {
	// profile: 0=conservative, 1=moderate, 2=aggressive, 3=very_aggressive
	var multiplier float64
	switch profile {
	case 0: // Very conservative
		multiplier = 2.0 + rand.Float64()*1.5 // 2.0x - 3.5x
	case 1: // Conservative 
		multiplier = 1.3 + rand.Float64()*0.7 // 1.3x - 2.0x
	case 2: // Moderate
		multiplier = 0.8 + rand.Float64()*0.6 // 0.8x - 1.4x
	case 3: // Aggressive
		multiplier = 0.3 + rand.Float64()*0.4 // 0.3x - 0.7x
	default:
		multiplier = 1.0
	}
	
	// Add realistic human variations
	finalMs := int(float64(baseMs) * multiplier)
	
	// Add random "thinking" pauses occasionally
	if rand.Float32() < 0.1 { // 10% chance of longer pause
		finalMs += rand.Intn(2000) + 500
	}
	
	return time.Duration(finalMs) * time.Millisecond
}
