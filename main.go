package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	utls "github.com/refraction-networking/utls"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ============================================================
// Global HTTP client with TLS fingerprinting
// ============================================================

var httpClient *http.Client
var warmUpCookies string
var warmUpOnce sync.Once

// warmUp visits notion.so → notion.com redirect chain to collect Cloudflare cookies.
// Without __cf_bm, _cfuvid, notion_browser_id, device_id, API returns trust-rule-denied.
func warmUp() {
	jar, _ := cookiejar.New(nil)
	jarClient := &http.Client{
		Transport: httpClient.Transport.(*http.Transport),
		Jar:       jar,
	}

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"

	// Visit 1: notion.so → notion.com redirect chain
	req, _ := http.NewRequest("GET", "https://www.notion.so", nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := jarClient.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Visit 2: notion.com (gets additional cookies like notion_sync_user_id)
	req2, _ := http.NewRequest("GET", "https://www.notion.com", nil)
	req2.Header.Set("User-Agent", ua)
	req2.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp2, err := jarClient.Do(req2)
	if err == nil {
		io.Copy(io.Discard, resp2.Body)
		resp2.Body.Close()
	}

	// Collect ALL cookies from all domains
	var parts []string
	seen := map[string]bool{}
	for _, u := range []string{"https://www.notion.so", "https://notion.so", "https://www.notion.com", "https://notion.com"} {
		parsed, _ := url.Parse(u)
		for _, c := range jar.Cookies(parsed) {
			if c.Name == "token_v2" || c.Name == "notion_user_id" || c.Name == "cf_clearance" {
				continue
			}
			key := c.Name + "|" + c.Domain
			if seen[key] {
				continue
			}
			seen[key] = true
			parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
	}
	if len(parts) > 0 {
		warmUpCookies = strings.Join(parts, "; ")
		log.Printf("Warm-up collected %d cookies from %d domains", len(parts), len(seen))
	}
}

func createHTTPClient() *http.Client {
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			tcpConn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("tcp dial: %w", err)
			}
			// Fresh spec per connection (docs say don't reuse)
			spec, _ := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
			for i, ext := range spec.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = []string{"http/1.1"}
					spec.Extensions[i] = alpn
					break
				}
			}
			uConn := utls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloCustom)
			if err := uConn.ApplyPreset(&spec); err != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("apply preset: %w", err)
			}
			if err := uConn.Handshake(); err != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("utls handshake: %w", err)
			}
			debugLog("utls handshake OK — JA3=Chrome, negotiated=%s", uConn.ConnectionState().NegotiatedProtocol)
			return uConn, nil
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
	}
}

// ============================================================
// APP_MODE
// ============================================================

var appMode string // "lite", "standard", "heavy"

// ============================================================
// Config & Account types
// ============================================================

type Account struct {
	TokenV2     string `json:"token_v2"`
	SpaceID     string `json:"space_id"`
	UserID      string `json:"user_id"`
	SpaceViewID string `json:"space_view_id"`
	UserName    string `json:"user_name"`
	UserEmail   string `json:"user_email"`
	CfClearance string `json:"cf_clearance,omitempty"` // optional Cloudflare cookie
}

const accountsFile = "accounts.json"
const apiKeyFile = ".apikey"
const notionClientVersion = "23.13.20260228.0625"

// API key for Bearer auth (empty = no auth required)
var apiKey string

// Debug mode — set NOTION2API_DEBUG=1 to log raw Notion responses
var debugMode bool

func initDebugMode() {
	debugMode = os.Getenv("NOTION2API_DEBUG") == "1"
}

// loadDotEnv reads .env file and sets env vars (simple key=value, no shell expansion)
func loadDotEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return // .env not found, skip
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Strip surrounding quotes
		if len(val) >= 2 && (val[0] == '\'' && val[len(val)-1] == '\'' || val[0] == '"' && val[len(val)-1] == '"') {
			val = val[1 : len(val)-1]
		}
		// Only set if not already set (env vars take priority)
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
	log.Println("Loaded .env file")
}

// ============================================================
// Model registry — matches Python model_registry.py exactly
// ============================================================

var modelMap = map[string]string{
	"claude-opus4.6":   "avocado-froyo-medium",
	"claude-opus4.7":   "apricot-sorbet-high",
	"claude-opus4.8":   "ambrosia-tart-high",
	"claude-sonnet4.6": "almond-croissant-low",
	"gemini-2.5flash":  "vertex-gemini-2.5-flash",
	"gemini-3.1pro":    "galette-medium-thinking",
	"gpt-5.2":          "oatmeal-cookie",
	"gpt-5.4":          "oval-kumquat-medium",
	"gpt-5.5":          "opal-quince-medium",
	"kimi-2.6":         "fireworks-kimi-k2.6",
}

var defaultModel = "claude-sonnet4.6"

// Only vertex-gemini-2.5-flash uses markdown-chat
var markdownChatModels = map[string]bool{
	"vertex-gemini-2.5-flash": true,
}

var accounts []Account

// ============================================================
// OpenAI-compatible request/response types
// ============================================================

type ChatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	Name       string          `json:"name,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

type ChatCompletionRequest struct {
	Model                string        `json:"model"`
	Messages             []ChatMessage `json:"messages"`
	Stream               bool          `json:"stream"`
	ConversationID       string        `json:"conversation_id,omitempty"` // heavy mode only
	Temperature          *float64      `json:"temperature,omitempty"`
	TopP                 *float64      `json:"top_p,omitempty"`
	N                    *int          `json:"n,omitempty"`
	MaxTokens            *int          `json:"max_tokens,omitempty"`
	MaxCompletionTokens  *int          `json:"max_completion_tokens,omitempty"`
	Stop                 interface{}   `json:"stop,omitempty"`
	PresencePenalty      *float64      `json:"presence_penalty,omitempty"`
	FrequencyPenalty     *float64      `json:"frequency_penalty,omitempty"`
	LogitBias            interface{}   `json:"logit_bias,omitempty"`
	Logprobs             *bool         `json:"logprobs,omitempty"`
	TopLogprobs          *int          `json:"top_logprobs,omitempty"`
	User                 string        `json:"user,omitempty"`
	Seed                 *int          `json:"seed,omitempty"`
	ResponseFormat       interface{}   `json:"response_format,omitempty"`
	Tools                interface{}   `json:"tools,omitempty"`
	ToolChoice           interface{}   `json:"tool_choice,omitempty"`
	ParallelToolCalls    *bool         `json:"parallel_tool_calls,omitempty"`
	ServiceTier          string        `json:"service_tier,omitempty"`
	StreamOptions        interface{}   `json:"stream_options,omitempty"`
}

type ChatCompletionChoice struct {
	Index        int          `json:"index"`
	Message      *ChatMessage `json:"message,omitempty"`
	Delta        *ChatMessage `json:"delta,omitempty"`
	FinishReason *string      `json:"finish_reason,omitempty"`
}

type UsageInfo struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type ChatCompletionResponse struct {
	ID                string                 `json:"id"`
	Object            string                 `json:"object"`
	Created           int64                  `json:"created"`
	Model             string                 `json:"model"`
	Choices           []ChatCompletionChoice `json:"choices"`
	Usage             *UsageInfo             `json:"usage,omitempty"`
	SystemFingerprint string                 `json:"system_fingerprint,omitempty"`
}

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type ModelsResponse struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

type ErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// ============================================================
// Helpers
// ============================================================

func genID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "chatcmpl-" + hex.EncodeToString(b)
}

func genUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func strPtr(s string) *string { return &s }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// contentRaw converts a plain string to json.RawMessage for ChatMessage.Content
func contentRaw(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return json.RawMessage(b)
}

// extractContentString normalizes ChatMessage.Content (json.RawMessage) to a plain string.
// Handles: null, "string", [{"type":"text","text":"..."}], [{"type":"image_url",...}]
func extractContentString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	// Try as plain string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Try as array of content parts (OpenAI multimodal format)
	var parts []struct {
		Type string          `json:"type"`
		Text string          `json:"text"`
		Raw  json.RawMessage `json:"image_url"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var texts []string
		for _, p := range parts {
			if p.Type == "text" && p.Text != "" {
				texts = append(texts, p.Text)
			}
		}
		return strings.Join(texts, "\n")
	}
	// Fallback: raw string representation
	return string(raw)
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error: struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		}{Message: msg, Type: "invalid_request_error", Code: fmt.Sprintf("%d", code)},
	})
}

func debugLog(format string, args ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// ============================================================
// System prompt sanitizer — strips injection patterns
// ============================================================

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you are [A-Z][a-zA-Z]+[,.]?\s*(an? )?(AI |autonomous )?agent[^.]*\.`),
	regexp.MustCompile(`(?i)you are (?:an? )?(?:AI |autonomous )?agent[^.]*\.`),
	regexp.MustCompile(`(?i)(?:you )?(?:have |has )?access to (?:terminal|file\s*system|web\s*search|browser|tools|memory)[^.]*\.`),
	regexp.MustCompile(`(?i)(?:you )?(?:can )?(?:execute|run) (?:commands?|scripts?|code|shell)[^.]*\.`),
	regexp.MustCompile(`(?i)(?:your|available) (?:tools?|capabilities|toolsets?)[^.]*(?:include|are|:)[^.]*\.`),
	regexp.MustCompile(`(?i)(?:execute|run|perform) (?:commands?|scripts?|code) and (?:return|report|output)[^.]*\.`),
	regexp.MustCompile(`(?i)hermes[^.]*\b(agent|assistant|bot)\b[^.]*\.`),
}

func sanitizeSystemPrompt(prompt string) string {
	sanitized := prompt
	for _, p := range injectionPatterns {
		sanitized = p.ReplaceAllString(sanitized, "")
	}
	return strings.TrimSpace(sanitized)
}

// ============================================================
// URL stripper — strips URLs from user messages when tool data present
// ============================================================

var urlPattern = regexp.MustCompile(`(?:https?://)?(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|raw\.githubusercontent\.com)[^\s\)"'>,]+|https?://[^\s\)"'>,]+|(?:github|gitlab|bitbucket)\.com\b`)

func stripURLs(text string) string {
	return strings.TrimSpace(urlPattern.ReplaceAllString(text, ""))
}

// ============================================================
// Lang tag stripping (matches Python _strip_lang_tags)
// ============================================================

var (
	reLangFull    = regexp.MustCompile(`(?s)<lang\b[^>]*>(.*?)</lang>`)
	reLangOpen    = regexp.MustCompile(`<lang\b[^>]*>`)
	reLangClose   = regexp.MustCompile(`</lang>`)
	rePrimaryAttr = regexp.MustCompile(`(?i)\bprimary="[a-zA-Z\-]{1,15}"\s*`)
	reAttrTail        = regexp.MustCompile(`^-?[a-zA-Z]{0,4}"\s*>\s*`)
	reReasoningPrefix = regexp.MustCompile(`(?i)^(?:general knowledge question[.!?]|simple (?:\w+ )+in \w+[.!?]|simple \w+[.!?]|simple (?:\w+ )*(?:question|request)\w*[.!?]|the user (?:wants|is asking)[^.]*[.!?]|this is (?:a )?(?:general|simple|straightforward)[^.]*[.!?]|no need to (?:search|look up)[^.]*[.!?]|search(?:ing)? (?:for|not needed)[^.]*[.!?]|a (?:simple|brief|quick|short) \w+[.!?])[\s]*`)
	// Trailing reasoning suffixes — same patterns but anchored at end of string
	reReasoningSuffix = regexp.MustCompile(`(?i)[.!?]\s*(?:general knowledge question|simple (?:\w+ )+in \w+|simple (?:\w+ )*(?:question|request)\w*|the user (?:wants|is asking)[^.]*|this is (?:a )?(?:general|simple|straightforward)[^.]*|no need to (?:search|look up)[^.]*|search(?:ing)? (?:for|not needed)[^.]*|a (?:simple|brief|quick|short) \w+)[.!?]$`)
	reOrphanLangOpen = regexp.MustCompile(`<lang\b[^>]*$`)
	// Input filtering — strip framework injection blocks before sending to Notion
	reMemoryContext = regexp.MustCompile(`(?s)<memory-context>.*?</memory-context>`)
	reHermesMemory  = regexp.MustCompile(`(?s)<hermes-memory>.*?</hermes-memory>`)
	reHonchoContext = regexp.MustCompile(`(?s)<honcho-context>.*?</honcho-context>`)
	// JSON artifact patterns — Notion AI tool call outputs that leak into responses
	reJSONSearchQuery  = regexp.MustCompile(`(?s)\{\s*"default"\s*:\s*\{\s*"questions"\s*:\s*\[.*?\]\s*\}\s*\}`)
	reJSONPageCreate   = regexp.MustCompile(`(?s)\{\s*"pages"\s*:\s*\[\{.*?\}\]\s*\}`)
	reJSONGeneric      = regexp.MustCompile(`(?s)\{\s*"(?:default|pages|results|questions|internal)"\s*:.*?\}`)
	// Reasoning paragraph patterns — long meta-descriptions from Notion AI
	reReasoningPara    = regexp.MustCompile(`(?is)(?:^|\n\n)(?:no (?:existing )?(?:docs?|documents?|results?) (?:found|were found)|the user (?:is asking|wants|has asked|is trying|needs)|let me (?:try|search|check|look|find|see|create|respond)|(?:since|because) the user|I(?:'ll| will| should| need to| can)? (?:try|search|check|create|find|look|plan|respond|provide)|I'm (?:checking|searching|looking|not sure)|(?:my earlier|the previous) (?:search|plan|document)|given the (?:ambiguity|scope|request)|the page creation failed|it seems there's an issue creating pages)[^.!?\n]{10,700}[.!?]`)
	// Notion structural markup
	reColumns = regexp.MustCompile(`(?i)</?column(?:s)?>`)
	reTableRow = regexp.MustCompile(`(?i)</?(?:table|row|cell|tr|td|th)(?:\s[^>]*)?>`)
)

func cleanNotionMarkup(text string) string {
	// 1. <lang ...>content</lang> → content
	text = reLangFull.ReplaceAllString(text, "$1")
	// 2. orphan </lang>
	text = reLangClose.ReplaceAllString(text, "")
	// 3. orphan <lang ...>
	text = reLangOpen.ReplaceAllString(text, "")
	// 3.5. truncated <lang ... (missing closing >)
	text = reOrphanLangOpen.ReplaceAllString(text, "")
	// 4. primary="zh-CN" fragments
	text = rePrimaryAttr.ReplaceAllString(text, "")
	// 5. attr tail fragments at line start
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = reAttrTail.ReplaceAllString(line, "")
	}
	text = strings.Join(lines, "\n")
	// 6. Notion structural markup (<columns>, <column>, <table>, <row>, <cell>)
	text = reColumns.ReplaceAllString(text, "")
	text = reTableRow.ReplaceAllString(text, "")
	return text
}

// stripJSONArtifacts removes balanced JSON-ish tool outputs starting with known keys.
func stripJSONArtifacts(text string) string {
	keys := []string{`"pages"`, `"default"`, `"internal"`, `"results"`, `"questions"`}
	for {
		start := -1
		for _, key := range keys {
			idx := strings.Index(text, "{"+key)
			if idx == -1 {
				idx = strings.Index(text, "{ "+key)
			}
			if idx >= 0 && (start == -1 || idx < start) {
				start = idx
			}
		}
		if start == -1 {
			return text
		}
		depth := 0
		inString := false
		escape := false
		end := -1
		for i := start; i < len(text); i++ {
			ch := text[i]
			if escape {
				escape = false
				continue
			}
			if ch == '\\' && inString {
				escape = true
				continue
			}
			if ch == '"' {
				inString = !inString
				continue
			}
			if inString {
				continue
			}
			if ch == '{' {
				depth++
			} else if ch == '}' {
				depth--
				if depth == 0 {
					end = i + 1
					break
				}
			}
		}
		if end == -1 {
			// Truncated JSON: drop from start onward.
			return strings.TrimSpace(text[:start])
		}
		text = strings.TrimSpace(text[:start] + "\n" + text[end:])
	}
}

// cleanResponseText removes reasoning prefixes, deduplicates content, and strips markup.
func cleanResponseText(text string) string {
	if text == "" {
		return text
	}

	// 1. Clean Notion markup (lang tags, br tags, etc.)
	text = cleanNotionMarkup(text)

	// 1.5. Bookend detection: if text starts+ends with same short reasoning fragment, strip both
	reBookend := regexp.MustCompile(`(?i)^(?:simple|greeting|knowledge|question|request|straightforward|brief|searching|no need|a (?:simple|brief|quick|short))[^.!?]{0,60}[.!?]`)
	if m := reBookend.FindString(text); len(m) > 5 && len(m) < 80 {
		rest := text[len(m):]
		if strings.HasSuffix(rest, m) {
			text = strings.TrimSpace(rest[:len(rest)-len(m)])
		} else {
			text = strings.TrimSpace(rest)
		}
	}

	// 2. Strip reasoning prefixes that leak from Notion AI
	text = reReasoningPrefix.ReplaceAllString(text, "")

	// 2.1. Strip JSON artifacts (search queries, page creation outputs)
	text = stripJSONArtifacts(text)
	text = reJSONSearchQuery.ReplaceAllString(text, "")
	text = reJSONPageCreate.ReplaceAllString(text, "")
	text = reJSONGeneric.ReplaceAllString(text, "")

	// 2.2. Strip reasoning paragraphs (long "The user is asking..." meta-descriptions)
	for i := 0; i < 4; i++ {
		cleaned := reReasoningPara.ReplaceAllString(text, "")
		if cleaned == text {
			break
		}
		text = cleaned
	}

	// 2.25. If response starts with English tool/reasoning meta before Indonesian answer, cut to answer.
	lowerText := strings.ToLower(text)
	if strings.HasPrefix(lowerText, "no results found") || strings.HasPrefix(lowerText, "no existing") || strings.HasPrefix(lowerText, "i didn't find") || strings.HasPrefix(lowerText, "the user ") || strings.HasPrefix(lowerText, "let me ") || strings.HasPrefix(lowerText, "i'll ") {
		markers := []string{"Tidak ", "Maaf,", "Berikut ", "Oke,", "Saya "}
		cut := -1
		for _, marker := range markers {
			if idx := strings.Index(text, marker); idx >= 0 && (cut == -1 || idx < cut) {
				cut = idx
			}
		}
		if cut > 0 {
			text = strings.TrimSpace(text[cut:])
		}
	}

	// 2.3. Strip Notion "(1/12)" style pagination artifacts
	rePagination := regexp.MustCompile(`\(\d+/\d+\)\s*`)
	text = rePagination.ReplaceAllString(text, "")

	// 2.4. Clean up excessive whitespace from stripped artifacts
	text = regexp.MustCompile(`\n{3,}`).ReplaceAllString(text, "\n\n")
	text = strings.TrimSpace(text)

	// 3. Deduplicate: if content appears twice (artifacted + clean), keep only the last copy
	paragraphs := strings.Split(text, "\n\n")
	if len(paragraphs) >= 2 {
		half := len(paragraphs) / 2
		firstHalf := strings.TrimSpace(strings.Join(paragraphs[:half], "\n\n"))
		secondHalf := strings.TrimSpace(strings.Join(paragraphs[half:], "\n\n"))
		if len(firstHalf) > 20 && len(secondHalf) > 20 {
			minLen := len(secondHalf)
			if minLen > 50 {
				minLen = 50
			}
			if strings.HasPrefix(firstHalf, secondHalf[:minLen]) {
				text = secondHalf
			} else if len(secondHalf) > 50 && strings.Contains(firstHalf, secondHalf[:50]) {
				// Fuzzy: secondHalf content already inside firstHalf → keep first (has more context)
				text = firstHalf
			}
		}
	}

	// 4. Strip trailing reasoning fragments (short meta-descriptions appended after content)
	lines := strings.Split(text, "\n")
	punctRunes := ".!?。！？）)"
	if len(lines) > 0 {
		lastLine := strings.TrimSpace(lines[len(lines)-1])
		if len(lastLine) > 0 && len(lastLine) < 60 {
			lastRunes := []rune(lastLine)
			lastChar := lastRunes[len(lastRunes)-1]
			isPunctuation := strings.ContainsRune(punctRunes, lastChar)
			if !isPunctuation {
				for i := len(lines) - 2; i >= 0; i-- {
					prev := strings.TrimSpace(lines[i])
					if prev == "" {
						continue
					}
					prevRunes := []rune(prev)
					prevLast := prevRunes[len(prevRunes)-1]
					if strings.ContainsRune(punctRunes, prevLast) {
						lines = lines[:len(lines)-1]
						text = strings.TrimSpace(strings.Join(lines, "\n"))
					}
					break
				}
			}
		}
	}

	// 5. Strip trailing reasoning prefix (e.g. "Simple greeting." appended after real content)
	lines = strings.Split(text, "\n")
	if len(lines) > 1 {
		lastLine := strings.TrimSpace(lines[len(lines)-1])
		if len(lastLine) > 0 && len(lastLine) < 60 && reReasoningPrefix.MatchString(lastLine) {
			hasContent := false
			for i := len(lines) - 2; i >= 0; i-- {
				if strings.TrimSpace(lines[i]) != "" {
					hasContent = true
					break
				}
			}
			if hasContent {
				lines = lines[:len(lines)-1]
				text = strings.TrimSpace(strings.Join(lines, "\n"))
			}
		}
	}

	// 6. Strip trailing reasoning suffix inline (e.g., "...😊Simple greeting in Indonesian.")
	// Locate a reasoning meta-pattern near the end and strip from there.
	reasoningTail := `(?i)(?:general knowledge question[.!?]|simple [^.!?]{1,60}[.!?]|the user (?:wants|is asking)[^.]*[.!?]|this is (?:a )?(?:general|simple|straightforward)[^.]*[.!?]|no need to (?:search|look up)[^.]*[.!?]|search(?:ing)? (?:for|not needed)[^.]*[.!?]|a (?:simple|brief|quick|short) [^.!?]{1,30}[.!?])`
	if len(text) > 80 {
		tail := text[len(text)-80:]
		re := regexp.MustCompile(reasoningTail)
		loc := re.FindStringIndex(tail)
		if loc != nil {
			cutAt := len(text) - 80 + loc[0]
			text = strings.TrimSpace(text[:cutAt])
		}
	}

	return strings.TrimSpace(text)
}

// cleanInputText strips framework injection blocks from user input before sending to Notion.
// Prevents memory-context, hermes-memory, honcho-context blocks from confusing Notion AI.
func cleanInputText(text string) string {
	if text == "" {
		return text
	}
	text = reMemoryContext.ReplaceAllString(text, "")
	text = reHermesMemory.ReplaceAllString(text, "")
	text = reHonchoContext.ReplaceAllString(text, "")
	return strings.TrimSpace(text)
}

// resolveModel maps friendly name → Notion internal model ID
func resolveModel(name string) (notionModel string, threadType string) {
	if name == "" {
		name = defaultModel
	}
	notionID, ok := modelMap[name]
	if !ok {
		// Try reverse: maybe user passed internal Notion ID directly
		for _, internal := range modelMap {
			if internal == name {
				notionID = internal
				ok = true
				break
			}
		}
	}
	if !ok {
		notionID = modelMap[defaultModel]
	}

	tt := "workflow"
	if markdownChatModels[notionID] {
		tt = "markdown-chat"
	}
	return notionID, tt
}

// ============================================================
// Account loading
// ============================================================

func loadAccounts() bool {
	// Priority: accounts.json > NOTION_ACCOUNTS env var (matches Python repo)
	data, err := os.ReadFile(accountsFile)
	if err != nil {
		// Fallback to NOTION_ACCOUNTS env var
		envData := os.Getenv("NOTION_ACCOUNTS")
		if envData == "" {
			return false
		}
		data = []byte(envData)
		log.Println("Loaded accounts from NOTION_ACCOUNTS env var")
	}
	if err := json.Unmarshal(data, &accounts); err != nil {
		log.Printf("Failed to parse accounts: %v", err)
		return false
	}
	return len(accounts) > 0
}

func saveAccounts() {
	data, err := json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal accounts: %v", err)
		return
	}
	if err := os.WriteFile(accountsFile, data, 0600); err != nil {
		log.Printf("Failed to write %s: %v", accountsFile, err)
	}
}

// ============================================================
// API Key management
// ============================================================

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "sk-" + hex.EncodeToString(b)
}

func loadAPIKey() {
	// Priority: API_KEY env var > .apikey file
	if envKey := os.Getenv("API_KEY"); envKey != "" {
		apiKey = envKey
		return
	}
	data, err := os.ReadFile(apiKeyFile)
	if err == nil {
		apiKey = strings.TrimSpace(string(data))
		return
	}
	// No API key found — auto-generate if accounts exist
	if len(accounts) > 0 {
		apiKey = generateAPIKey()
		saveAPIKey()
	}
}

func saveAPIKey() {
	if err := os.WriteFile(apiKeyFile, []byte(apiKey+"\n"), 0600); err != nil {
		log.Printf("Failed to write %s: %v", apiKeyFile, err)
	}
}

func regenerateAPIKey() {
	apiKey = generateAPIKey()
	saveAPIKey()
}

// requireAuth is a middleware that checks Bearer token
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiKey == "" {
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: struct {
					Message string `json:"message"`
					Type    string `json:"type"`
					Code    string `json:"code"`
				}{
					Message: "Missing or invalid Authorization header. Use: Bearer <api_key>",
					Type:    "invalid_request_error",
					Code:    "unauthorized",
				},
			})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if token != apiKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: struct {
					Message string `json:"message"`
					Type    string `json:"type"`
					Code    string `json:"code"`
				}{
					Message: "Invalid API key",
					Type:    "invalid_request_error",
					Code:    "unauthorized",
				},
			})
			return
		}
		next(w, r)
	}
}

func promptAccounts() {
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║       Notion2API Go — First Run Setup            ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println("\nPaste your NOTION_ACCOUNTS JSON (single account):")
	fmt.Println(`Example:
{
  "token_v2": "v03:xxxxxxxx",
  "space_id": "xxxx-xxxx",
  "user_id": "xxxx-xxxx",
  "space_view_id": "xxxx-xxxx",
  "user_name": "Your Name",
  "user_email": "you@email.com"
}`)
	fmt.Print("\n> ")

	var acc Account
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&acc); err != nil {
		log.Fatalf("Invalid JSON: %v", err)
	}
	if acc.TokenV2 == "" || acc.SpaceID == "" || acc.UserID == "" {
		log.Fatal("token_v2, space_id, and user_id are required")
	}
	accounts = append(accounts, acc)
	saveAccounts()
	regenerateAPIKey()
	fmt.Printf("\n✓ Account saved to %s\n", accountsFile)
	fmt.Printf("🔑 API Key: %s\n", apiKey)
	fmt.Printf("   (saved to %s — use this as Bearer token)\n\n", apiKeyFile)
}

func getAccount() Account {
	return accounts[0]
}

// ============================================================
// Cookie builder
// ============================================================

func buildCookieHeader(acc Account) string {
	parts := []string{
		fmt.Sprintf("token_v2=%s", acc.TokenV2),
		fmt.Sprintf("notion_user_id=%s", acc.UserID),
	}
	if acc.CfClearance != "" {
		parts = append(parts, fmt.Sprintf("cf_clearance=%s", acc.CfClearance))
	}
	if warmUpCookies != "" {
		parts = append(parts, warmUpCookies)
	}
	return strings.Join(parts, "; ")
}

// ============================================================
// SQLite Conversation Persistence (Heavy Mode)
// ============================================================

type ConversationManager struct {
	db *sql.DB
}

type Conversation struct {
	ID             string
	CreatedAt      int64
	NextRoundIndex int
	ThreadID       string
	ThreadModel    string
}

type Message struct {
	ID             int64
	ConversationID string
	Role           string
	Content        string
	Thinking       string
	CreatedAt      int64
}

type SlidingWindowEntry struct {
	ID                int64
	ConversationID    string
	RoundNumber       int
	UserContent       string
	AssistantContent  string
	AssistantThinking string
	CompressStatus    string
	CreatedAt         int64
}

var convManager *ConversationManager

func NewConversationManager(dbPath string) (*ConversationManager, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Enable WAL mode and foreign keys
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	cm := &ConversationManager{db: db}
	if err := cm.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	log.Printf("SQLite DB initialized at %s", dbPath)
	return cm, nil
}

func (cm *ConversationManager) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS conversations (
			id TEXT PRIMARY KEY,
			created_at INTEGER,
			next_round_index INTEGER DEFAULT 0,
			thread_id TEXT,
			thread_model TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			conversation_id TEXT,
			role TEXT,
			content TEXT,
			thinking TEXT DEFAULT '',
			created_at INTEGER,
			FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS sliding_window (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			conversation_id TEXT NOT NULL,
			round_number INTEGER NOT NULL,
			user_content TEXT NOT NULL,
			assistant_content TEXT NOT NULL,
			assistant_thinking TEXT DEFAULT '',
			compress_status TEXT DEFAULT 'active',
			created_at INTEGER NOT NULL,
			FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS compressed_summaries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			conversation_id TEXT NOT NULL,
			round_index INTEGER NOT NULL,
			user_content TEXT NOT NULL,
			assistant_content TEXT NOT NULL,
			summary TEXT,
			compress_status TEXT DEFAULT 'pending',
			created_at INTEGER NOT NULL,
			FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
	}
	for _, q := range queries {
		if _, err := cm.db.Exec(q); err != nil {
			return fmt.Errorf("exec migrate: %w\nquery: %s", err, q)
		}
	}
	return nil
}

func (cm *ConversationManager) NewConversation() string {
	id := genUUID()
	now := time.Now().Unix()
	_, err := cm.db.Exec(
		"INSERT INTO conversations (id, created_at, next_round_index, thread_id, thread_model) VALUES (?, ?, 0, '', '')",
		id, now,
	)
	if err != nil {
		log.Printf("NewConversation: insert failed: %v", err)
	}
	return id
}

func (cm *ConversationManager) ConversationExists(id string) bool {
	var count int
	err := cm.db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", id).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func (cm *ConversationManager) GetMessages(convID string, limit int) []Message {
	rows, err := cm.db.Query(
		"SELECT id, conversation_id, role, content, thinking, created_at FROM messages WHERE conversation_id = ? ORDER BY id DESC LIMIT ?",
		convID, limit,
	)
	if err != nil {
		log.Printf("GetMessages: query failed: %v", err)
		return nil
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content, &m.Thinking, &m.CreatedAt); err != nil {
			continue
		}
		msgs = append(msgs, m)
	}
	// Reverse to chronological order
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	return msgs
}

func (cm *ConversationManager) SaveMessage(convID, role, content, thinking string) {
	now := time.Now().Unix()
	_, err := cm.db.Exec(
		"INSERT INTO messages (conversation_id, role, content, thinking, created_at) VALUES (?, ?, ?, ?, ?)",
		convID, role, content, thinking, now,
	)
	if err != nil {
		log.Printf("SaveMessage: insert failed: %v", err)
	}
}

func (cm *ConversationManager) SaveSlidingWindowRound(convID string, roundNum int, userContent, assistantContent, assistantThinking string) {
	now := time.Now().Unix()
	_, err := cm.db.Exec(
		"INSERT INTO sliding_window (conversation_id, round_number, user_content, assistant_content, assistant_thinking, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		convID, roundNum, userContent, assistantContent, assistantThinking, now,
	)
	if err != nil {
		log.Printf("SaveSlidingWindowRound: insert failed: %v", err)
	}
}

func (cm *ConversationManager) GetActiveSlidingWindow(convID string, maxRounds int) []SlidingWindowEntry {
	rows, err := cm.db.Query(
		"SELECT id, conversation_id, round_number, user_content, assistant_content, assistant_thinking, compress_status, created_at FROM sliding_window WHERE conversation_id = ? AND compress_status = 'active' ORDER BY round_number DESC LIMIT ?",
		convID, maxRounds,
	)
	if err != nil {
		log.Printf("GetActiveSlidingWindow: query failed: %v", err)
		return nil
	}
	defer rows.Close()

	var entries []SlidingWindowEntry
	for rows.Next() {
		var e SlidingWindowEntry
		if err := rows.Scan(&e.ID, &e.ConversationID, &e.RoundNumber, &e.UserContent, &e.AssistantContent, &e.AssistantThinking, &e.CompressStatus, &e.CreatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	// Reverse to chronological order
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries
}

func (cm *ConversationManager) GetCompressedSummaries(convID string) []string {
	rows, err := cm.db.Query(
		"SELECT COALESCE(summary, user_content || ' → ' || assistant_content) FROM compressed_summaries WHERE conversation_id = ? ORDER BY round_index ASC",
		convID,
	)
	if err != nil {
		log.Printf("GetCompressedSummaries: query failed: %v", err)
		return nil
	}
	defer rows.Close()

	var summaries []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			continue
		}
		summaries = append(summaries, s)
	}
	return summaries
}

func (cm *ConversationManager) GetThreadID(convID string) string {
	var threadID string
	err := cm.db.QueryRow("SELECT COALESCE(thread_id, '') FROM conversations WHERE id = ?", convID).Scan(&threadID)
	if err != nil {
		return ""
	}
	return threadID
}

func (cm *ConversationManager) SetThreadID(convID, threadID, model string) {
	_, err := cm.db.Exec(
		"UPDATE conversations SET thread_id = ?, thread_model = ? WHERE id = ?",
		threadID, model, convID,
	)
	if err != nil {
		log.Printf("SetThreadID: update failed: %v", err)
	}
}

func (cm *ConversationManager) ClearThread(convID string) {
	_, err := cm.db.Exec(
		"UPDATE conversations SET thread_id = '', thread_model = '' WHERE id = ?",
		convID,
	)
	if err != nil {
		log.Printf("ClearThread: update failed: %v", err)
	}
}

func (cm *ConversationManager) GetNextRoundIndex(convID string) int {
	var idx int
	err := cm.db.QueryRow("SELECT next_round_index FROM conversations WHERE id = ?", convID).Scan(&idx)
	if err != nil {
		return 0
	}
	return idx
}

func (cm *ConversationManager) IncrementRoundIndex(convID string) {
	_, err := cm.db.Exec(
		"UPDATE conversations SET next_round_index = next_round_index + 1 WHERE id = ?",
		convID,
	)
	if err != nil {
		log.Printf("IncrementRoundIndex: update failed: %v", err)
	}
}

func (cm *ConversationManager) CompressOldMessages(convID string) {
	// Move sliding window entries beyond 16 messages (8 rounds) to compressed_summaries
	// Mark old entries as 'compressed'
	const maxActiveRounds = 8

	rows, err := cm.db.Query(
		"SELECT id, round_number, user_content, assistant_content FROM sliding_window WHERE conversation_id = ? AND compress_status = 'active' ORDER BY round_number ASC",
		convID,
	)
	if err != nil {
		log.Printf("CompressOldMessages: query failed: %v", err)
		return
	}
	defer rows.Close()

	var allEntries []struct {
		ID               int64
		RoundNumber      int
		UserContent      string
		AssistantContent string
	}
	for rows.Next() {
		var e struct {
			ID               int64
			RoundNumber      int
			UserContent      string
			AssistantContent string
		}
		if err := rows.Scan(&e.ID, &e.RoundNumber, &e.UserContent, &e.AssistantContent); err != nil {
			continue
		}
		allEntries = append(allEntries, e)
	}

	if len(allEntries) <= maxActiveRounds {
		return
	}

	// Compress oldest entries
	toCompress := allEntries[:len(allEntries)-maxActiveRounds]
	now := time.Now().Unix()
	for _, e := range toCompress {
		// Insert into compressed_summaries
		cm.db.Exec(
			"INSERT INTO compressed_summaries (conversation_id, round_index, user_content, assistant_content, summary, compress_status, created_at) VALUES (?, ?, ?, ?, NULL, 'pending', ?)",
			convID, e.RoundNumber, e.UserContent, e.AssistantContent, now,
		)
		// Mark as compressed in sliding window
		cm.db.Exec(
			"UPDATE sliding_window SET compress_status = 'compressed' WHERE id = ?",
			e.ID,
		)
	}
}

// GetTranscriptForConversation builds full transcript for heavy mode
func (cm *ConversationManager) GetTranscriptForConversation(convID string, newPrompt string, model string, acc Account) []map[string]interface{} {
	notionModel, threadType := resolveModel(model)

	transcript := []map[string]interface{}{
		{
			"id":   genUUID(),
			"type": "config",
			"value": map[string]interface{}{
				"type":          threadType,
				"model":         notionModel,
				"modelFromUser": true,
				"useWebSearch":  true,
			},
		},
		{
			"id":   genUUID(),
			"type": "context",
			"value": map[string]interface{}{
				"timezone":        "Asia/Jakarta",
				"currentDatetime": time.Now().Format(time.RFC3339),
				"userId":          acc.UserID,
				"spaceId":         acc.SpaceID,
			},
		},
	}

	// Get compressed summaries for context
	summaries := cm.GetCompressedSummaries(convID)
	if len(summaries) > 0 {
		summaryText := "Previous conversation summary:\n" + strings.Join(summaries, "\n---\n")
		summaryText = sanitizeSystemPrompt(summaryText)
		transcript = append(transcript, map[string]interface{}{
			"id":    genUUID(),
			"type":  "user",
			"value": [][]string{{summaryText}},
		})
	}

	// Get active sliding window (last 8 rounds = 16 messages)
	windowEntries := cm.GetActiveSlidingWindow(convID, 8)
	for _, entry := range windowEntries {
		// User message
		transcript = append(transcript, map[string]interface{}{
			"id":        genUUID(),
			"type":      "user",
			"value":     [][]string{{entry.UserContent}},
			"userId":    acc.UserID,
			"createdAt": time.Unix(entry.CreatedAt, 0).Format(time.RFC3339),
		})
		// Assistant response
		assistantValue := []map[string]interface{}{
			{"type": "text", "content": entry.AssistantContent},
		}
		transcript = append(transcript, map[string]interface{}{
			"id":    genUUID(),
			"type":  "agent-inference",
			"value": assistantValue,
		})
	}

	// Add the new user prompt (sanitized)
	sanitizedPrompt := sanitizeSystemPrompt(newPrompt)
	transcript = append(transcript, map[string]interface{}{
		"id":        genUUID(),
		"type":      "user",
		"value":     [][]string{{sanitizedPrompt}},
		"userId":    acc.UserID,
		"createdAt": time.Now().Format(time.RFC3339),
	})

	return transcript
}

// ============================================================
// HTTP handlers
// ============================================================

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":    "notion2api-go",
		"version": "3.0.0",
		"mode":    appMode,
		"endpoints": []string{
			"POST /v1/chat/completions",
			"GET  /v1/models",
			"GET  /health",
			"GET  /",
		},
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"accounts": len(accounts),
		"mode":     appMode,
		"debug":    debugMode,
	})
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	var models []ModelInfo
	for friendly := range modelMap {
		models = append(models, ModelInfo{
			ID:      friendly,
			Object:  "model",
			Created: time.Now().Unix(),
			OwnedBy: "notion",
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ModelsResponse{Object: "list", Data: models})
}

// ============================================================
// Notion API — Pre-create thread (workflow mode)
// ============================================================

func createThread(acc Account, threadID, threadType string) bool {
	payload := map[string]interface{}{
		"requestId": genUUID(),
		"transactions": []map[string]interface{}{
			{
				"id":      genUUID(),
				"spaceId": acc.SpaceID,
				"operations": []map[string]interface{}{
					{
						"pointer": map[string]interface{}{
							"table":   "thread",
							"id":      threadID,
							"spaceId": acc.SpaceID,
						},
						"path":    []string{},
						"command": "set",
						"args": map[string]interface{}{
							"id":               threadID,
							"version":          1,
							"parent_id":        acc.SpaceID,
							"parent_table":     "space",
							"space_id":         acc.SpaceID,
							"created_time":     time.Now().UnixMilli(),
							"created_by_id":    acc.UserID,
							"created_by_table": "notion_user",
							"messages":         []interface{}{},
							"data":             map[string]interface{}{},
							"alive":            true,
							"type":             threadType,
						},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", "https://www.notion.so/api/v3/saveTransactions", bytes.NewReader(body))
	if err != nil {
		log.Printf("createThread: failed to create request: %v", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", buildCookieHeader(acc))
	req.Header.Set("x-notion-active-user-header", acc.UserID)
	req.Header.Set("x-notion-space-id", acc.SpaceID)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("createThread: request failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("createThread: HTTP %d: %s", resp.StatusCode, truncate(string(b), 300))
		return false
	}
	return true
}

// ============================================================
// Notion API — Stream from runInferenceTranscript
// ============================================================

func buildTranscript(req ChatCompletionRequest, acc Account, notionModel, threadType string) []map[string]interface{} {
	transcript := []map[string]interface{}{
		{
			"id":   genUUID(),
			"type": "config",
			"value": map[string]interface{}{
				"type":          threadType,
				"model":         notionModel,
				"modelFromUser": true,
				"useWebSearch":  true,
			},
		},
		{
			"id":   genUUID(),
			"type": "context",
			"value": map[string]interface{}{
				"timezone":        "Asia/Jakarta",
				"currentDatetime": time.Now().Format(time.RFC3339),
				"userId":          acc.UserID,
				"spaceId":         acc.SpaceID,
			},
		},
	}

	for _, msg := range req.Messages {
		switch msg.Role {
		case "system":
			transcript = append(transcript, map[string]interface{}{
				"id":        genUUID(),
				"type":      "user",
				"value":     [][]string{{"[System]: " + cleanInputText(extractContentString(msg.Content))}},
				"userId":    acc.UserID,
				"createdAt": time.Now().Format(time.RFC3339Nano),
			})
		case "user":
			transcript = append(transcript, map[string]interface{}{
				"id":        genUUID(),
				"type":      "user",
				"value":     [][]string{{cleanInputText(extractContentString(msg.Content))}},
				"userId":    acc.UserID,
				"createdAt": time.Now().Format(time.RFC3339Nano),
			})
		case "assistant":
			transcript = append(transcript, map[string]interface{}{
				"id":    genUUID(),
				"type":  "assistant",
				"value": extractContentString(msg.Content),
			})
		case "tool":
			// Tool results — treat as user context for Notion
			content := cleanInputText(extractContentString(msg.Content))
			if content != "" {
				transcript = append(transcript, map[string]interface{}{
					"id":        genUUID(),
					"type":      "user",
					"value":     [][]string{{"[Tool Result]: " + content}},
					"userId":    acc.UserID,
					"createdAt": time.Now().Format(time.RFC3339Nano),
				})
			}
		default:
			// Unknown role — treat as user message
			content := cleanInputText(extractContentString(msg.Content))
			if content != "" {
				transcript = append(transcript, map[string]interface{}{
					"id":        genUUID(),
					"type":      "user",
					"value":     [][]string{{fmt.Sprintf("[%s]: %s", msg.Role, content)}},
					"userId":    acc.UserID,
					"createdAt": time.Now().Format(time.RFC3339Nano),
				})
			}
		}
	}

	return transcript
}

// buildLiteTranscript builds minimal transcript for lite mode
func buildLiteTranscript(req ChatCompletionRequest, acc Account, notionModel, threadType string) []map[string]interface{} {
	// Get last user message
	lastUserMsg := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			lastUserMsg = cleanInputText(extractContentString(req.Messages[i].Content))
			break
		}
	}

	transcript := []map[string]interface{}{
		{
			"id":   genUUID(),
			"type": "config",
			"value": map[string]interface{}{
				"type":          threadType,
				"model":         notionModel,
				"modelFromUser": true,
			},
		},
		{
			"id":    genUUID(),
			"type":  "user",
			"value": [][]string{{lastUserMsg}},
		},
	}
	return transcript
}

func notionStreamRequest(ctx context.Context, acc Account, payload map[string]interface{}) (*http.Response, error) {
	warmUpOnce.Do(warmUp)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	debugLog("Notion request payload (truncated): %s", truncate(string(body), 2000))

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://www.notion.so/api/v3/runInferenceTranscript",
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-ndjson")
	cookieHeader := buildCookieHeader(acc)
	debugLog("Cookie header (%d bytes): %s", len(cookieHeader), truncate(cookieHeader, 600))
	req.Header.Set("Cookie", cookieHeader)
	req.Header.Set("x-notion-active-user-header", acc.UserID)
	req.Header.Set("x-notion-space-id", acc.SpaceID)
	req.Header.Set("notion-audit-log-platform", "web")
	req.Header.Set("notion-client-version", notionClientVersion)
	req.Header.Set("Origin", "https://www.notion.so")
	req.Header.Set("Referer", "https://www.notion.so/ai")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notion request: %w", err)
	}

	debugLog("Notion response: status=%d content-type=%s content-length=%d",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.ContentLength)

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("Notion API returned %d: %s", resp.StatusCode, truncate(string(b), 500))
	}

	return resp, nil
}

// ============================================================
// NDJSON Parser — matches Python stream_parser.py format
// ============================================================

// extractTextFromNDJSON parses a Notion NDJSON line and extracts text content.
// Returns extracted text (may be empty) and whether stream is done.
func extractTextFromNDJSON(line string) (text string, done bool, source string) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		return "", false, ""
	}

	dataType := strings.ToLower(fmt.Sprintf("%v", obj["type"]))

	debugLog("NDJSON type=%s line=%s", dataType, truncate(line, 500))

	// Type: done
	if dataType == "done" || dataType == "complete" || dataType == "stream_end" {
		return "", true, "done"
	}

	// Type: patch-start → may contain error from Notion
	if dataType == "patch-start" {
		if data, ok := obj["data"].(map[string]interface{}); ok {
			if sArr, ok := data["s"].([]interface{}); ok {
				for _, s := range sArr {
					if sMap, ok := s.(map[string]interface{}); ok {
						if typ, _ := sMap["type"].(string); typ == "error" {
							msg, _ := sMap["message"].(string)
							subType, _ := sMap["subType"].(string)
							log.Printf("Notion ERROR: %s (subType=%s)", msg, subType)
							if msg != "" {
								return "Error: " + msg, true, "error"
							}
						}
					}
				}
			}
		}
		return "", false, ""
	}

	// Type: record-map → skip in streaming (patches/markdown-chat already contain text)
	// Record-map is final state but would duplicate incremental content.
	if dataType == "record-map" {
		return "", false, "record-map"
	}

	// Type: markdown-chat → direct text
	if dataType == "markdown-chat" {
		text = extractMarkdownChatText(obj["value"])
		if text != "" {
			text = cleanNotionMarkup(text)
			debugLog("markdown-chat extracted: %s", truncate(text, 200))
		}
		return text, false, "markdown-chat"
	}

	// Type: patch → extract from v array
	if dataType != "patch" {
		return "", false, ""
	}

	patchesRaw, ok := obj["v"].([]interface{})
	if !ok {
		return "", false, "patch"
	}

	for _, patchRaw := range patchesRaw {
		patch, ok := patchRaw.(map[string]interface{})
		if !ok {
			continue
		}
		patchText := extractTextFromPatch(patch)
		if patchText != "" {
			patchText = cleanNotionMarkup(patchText)
			text += patchText
		}
	}

	return text, false, "patch"
}

// extractTextFromPatch extracts text from a single patch object.
func extractTextFromPatch(patch map[string]interface{}) string {
	op := fmt.Sprintf("%v", patch["o"])

	if op == "a" {
		v := patch["v"]
		if vMap, ok := v.(map[string]interface{}); ok {
			// Pattern: v.value is array of {type:"text", content:"..."}
			if valArr, ok := vMap["value"].([]interface{}); ok {
				var parts []string
				for _, item := range valArr {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if content, ok := itemMap["content"].(string); ok && content != "" {
							parts = append(parts, content)
						}
					}
				}
				return strings.Join(parts, "")
			}
			// Pattern: v.content is string (sub value block creation)
			if content, ok := vMap["content"].(string); ok && content != "" {
				return content
			}
			// Pattern: markdown-chat type
			if mtype, ok := vMap["type"].(string); ok && strings.ToLower(mtype) == "markdown-chat" {
				return extractMarkdownChatText(vMap["value"])
			}
		}
	}

	if op == "x" {
		if text, ok := patch["v"].(string); ok {
			return text
		}
	}

	if op == "p" {
		path := normalizePath(patch)
		if strings.Contains(path, "/content") || strings.Contains(path, "/text") {
			if text, ok := patch["v"].(string); ok {
				return text
			}
		}
	}

	return ""
}

// extractFromRecordMap extracts final content from a record-map NDJSON line.
func extractFromRecordMap(data map[string]interface{}) string {
	recordMap, ok := data["recordMap"].(map[string]interface{})
	if !ok {
		return ""
	}
	threadMsgs, ok := recordMap["thread_message"].(map[string]interface{})
	if !ok {
		return ""
	}

	var bestContent string
	for _, msgData := range threadMsgs {
		msgMap, ok := msgData.(map[string]interface{})
		if !ok {
			continue
		}
		outerValue, ok := msgMap["value"].(map[string]interface{})
		if !ok {
			continue
		}
		innerValue, ok := outerValue["value"].(map[string]interface{})
		if !ok {
			continue
		}
		step, ok := innerValue["step"].(map[string]interface{})
		if !ok {
			continue
		}
		content := extractTextFromStep(step)
		if content != "" {
			bestContent = content
		}
	}
	return bestContent
}

// extractTextFromStep extracts text from a step object in record-map
func extractTextFromStep(step map[string]interface{}) string {
	if val := step["value"]; val != nil {
		if s, ok := val.(string); ok {
			return s
		}
		if arr, ok := val.([]interface{}); ok {
			return extractMarkdownChatText(arr)
		}
	}
	if text, ok := step["text"].(string); ok {
		return text
	}
	if content, ok := step["content"].(string); ok {
		return content
	}
	return ""
}

// extractMarkdownChatText recursively extracts text from markdown-chat value.
func extractMarkdownChatText(value interface{}) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	if arr, ok := value.([]interface{}); ok {
		var parts []string
		for _, item := range arr {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
				continue
			}
			if itemMap, ok := item.(map[string]interface{}); ok {
				if t, ok := itemMap["type"].(string); ok && strings.ToLower(t) == "text" {
					if content, ok := itemMap["content"].(string); ok && content != "" {
						parts = append(parts, content)
						continue
					}
				}
				for _, key := range []string{"value", "content", "text"} {
					if nested := extractMarkdownChatText(itemMap[key]); nested != "" {
						parts = append(parts, nested)
						break
					}
				}
			}
		}
		return strings.Join(parts, "")
	}
	if obj, ok := value.(map[string]interface{}); ok {
		for _, key := range []string{"value", "content", "text"} {
			if nested := extractMarkdownChatText(obj[key]); nested != "" {
				return nested
			}
		}
	}
	return ""
}

// normalizePath converts path/p/at field to a "/" separated string
func normalizePath(patch map[string]interface{}) string {
	for _, key := range []string{"path", "p", "pointer", "at"} {
		raw := patch[key]
		if raw == nil {
			continue
		}
		if arr, ok := raw.([]interface{}); ok {
			parts := make([]string, len(arr))
			for i, p := range arr {
				parts[i] = fmt.Sprintf("%v", p)
			}
			return "/" + strings.Join(parts, "/")
		}
		return fmt.Sprintf("%v", raw)
	}
	return ""
}

// ============================================================
// Chat completions handler — routes by APP_MODE
// ============================================================

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChatCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}

	if len(req.Messages) == 0 {
		writeError(w, 400, "messages required")
		return
	}

	acc := getAccount()

	switch appMode {
	case "lite":
		handleLiteRequest(w, r, req, acc)
	case "standard":
		handleStandardRequest(w, r, req, acc)
	case "heavy":
		handleHeavyRequest(w, r, req, acc)
	default:
		handleStandardRequest(w, r, req, acc)
	}
}

// ============================================================
// Lite mode handler — minimal transcript, no context
// ============================================================

func handleLiteRequest(w http.ResponseWriter, r *http.Request, req ChatCompletionRequest, acc Account) {
	notionModel, threadType := resolveModel(req.Model)
	chatID := genUUID()

	log.Printf("[LITE] Chat request: model=%s → notion=%s (%s), stream=%v",
		req.Model, notionModel, threadType, req.Stream)

	if threadType == "workflow" {
		if !createThread(acc, chatID, threadType) {
			log.Printf("Warning: thread pre-creation failed, continuing anyway")
		}
	}

	transcript := buildLiteTranscript(req, acc, notionModel, threadType)

	payload := map[string]interface{}{
		"traceId":                       genUUID(),
		"spaceId":                       acc.SpaceID,
		"threadId":                      chatID,
		"threadType":                    threadType,
		"createThread":                  true,
		"generateTitle":                 true,
		"saveAllThreadOperations":       true,
		"setUnreadState":                true,
		"isPartialTranscript":           threadType == "markdown-chat",
		"asPatchResponse":               true,
		"isUserInAnySalesAssistedSpace": false,
		"isSpaceSalesAssisted":          false,
		"threadParentPointer": map[string]interface{}{
			"table":   "space",
			"id":      acc.SpaceID,
			"spaceId": acc.SpaceID,
		},
		"transcript": transcript,
		"debugOverrides": map[string]interface{}{
			"emitAgentSearchExtractedResults": true,
			"cachedInferences":                map[string]interface{}{},
			"annotationInferences":            map[string]interface{}{},
			"emitInferences":                  false,
		},
	}

	resp, err := notionStreamRequest(r.Context(), acc, payload)
	if err != nil {
		log.Printf("[LITE] Notion API error: %v", err)
		writeError(w, 502, fmt.Sprintf("Notion API error: %v", err))
		return
	}
	defer resp.Body.Close()

	if req.Stream {
		handleStreamResponse(w, r.Context(), resp.Body, chatID, req.Model)
	} else {
		handleNonStreamResponse(w, resp.Body, chatID, req.Model)
	}
}

// ============================================================
// Standard mode handler — full context, stateless (current behavior)
// ============================================================

func handleStandardRequest(w http.ResponseWriter, r *http.Request, req ChatCompletionRequest, acc Account) {
	notionModel, threadType := resolveModel(req.Model)
	chatID := genUUID()

	log.Printf("[STANDARD] Chat request: model=%s → notion=%s (%s), stream=%v",
		req.Model, notionModel, threadType, req.Stream)

	transcript := buildTranscript(req, acc, notionModel, threadType)

	payload := map[string]interface{}{
		"traceId":                       genUUID(),
		"spaceId":                       acc.SpaceID,
		"threadId":                      chatID,
		"threadType":                    threadType,
		"createThread":                  true,
		"generateTitle":                 true,
		"saveAllThreadOperations":       true,
		"setUnreadState":                true,
		"isPartialTranscript":           threadType == "markdown-chat",
		"asPatchResponse":               true,
		"isUserInAnySalesAssistedSpace": false,
		"isSpaceSalesAssisted":          false,
		"threadParentPointer": map[string]interface{}{
			"table":   "space",
			"id":      acc.SpaceID,
			"spaceId": acc.SpaceID,
		},
		"transcript": transcript,
		"debugOverrides": map[string]interface{}{
			"emitAgentSearchExtractedResults": true,
			"cachedInferences":                map[string]interface{}{},
			"annotationInferences":            map[string]interface{}{},
			"emitInferences":                  false,
		},
	}

	resp, err := notionStreamRequest(r.Context(), acc, payload)
	if err != nil {
		log.Printf("[STANDARD] Notion API error: %v", err)
		writeError(w, 502, fmt.Sprintf("Notion API error: %v", err))
		return
	}
	defer resp.Body.Close()

	if req.Stream {
		handleStreamResponse(w, r.Context(), resp.Body, chatID, req.Model)
	} else {
		handleNonStreamResponse(w, resp.Body, chatID, req.Model)
	}
}

// ============================================================
// Heavy mode handler — SQLite conversation persistence
// ============================================================

func handleHeavyRequest(w http.ResponseWriter, r *http.Request, req ChatCompletionRequest, acc Account) {
	if convManager == nil {
		writeError(w, 500, "Heavy mode: conversation manager not initialized")
		return
	}

	notionModel, threadType := resolveModel(req.Model)
	chatID := genUUID()

	// Get or create conversation
	convID := req.ConversationID
	isNew := false
	if convID == "" || !convManager.ConversationExists(convID) {
		convID = convManager.NewConversation()
		isNew = true
	}

	log.Printf("[HEAVY] Chat request: model=%s → notion=%s (%s), stream=%v, convID=%s (new=%v)",
		req.Model, notionModel, threadType, req.Stream, convID, isNew)

	// Save new user message to DB
	lastUserMsg := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			lastUserMsg = cleanInputText(extractContentString(req.Messages[i].Content))
			break
		}
	}
	convManager.SaveMessage(convID, "user", lastUserMsg, "")

	// Check if model changed — clear thread if so
	existingThreadID := convManager.GetThreadID(convID)
	if existingThreadID != "" {
		// Thread exists, we can reuse it
		chatID = existingThreadID
	} else {
		if threadType == "workflow" {
			if !createThread(acc, chatID, threadType) {
				log.Printf("Warning: thread pre-creation failed, continuing anyway")
			}
		}
		convManager.SetThreadID(convID, chatID, req.Model)
	}

	// Build transcript from DB history
	transcript := convManager.GetTranscriptForConversation(convID, lastUserMsg, req.Model, acc)

	payload := map[string]interface{}{
		"traceId":                       genUUID(),
		"spaceId":                       acc.SpaceID,
		"threadId":                      chatID,
		"threadType":                    threadType,
		"createThread":                  true,
		"generateTitle":                 true,
		"saveAllThreadOperations":       true,
		"setUnreadState":                true,
		"isPartialTranscript":           threadType == "markdown-chat",
		"asPatchResponse":               true,
		"isUserInAnySalesAssistedSpace": false,
		"isSpaceSalesAssisted":          false,
		"threadParentPointer": map[string]interface{}{
			"table":   "space",
			"id":      acc.SpaceID,
			"spaceId": acc.SpaceID,
		},
		"transcript": transcript,
		"debugOverrides": map[string]interface{}{
			"emitAgentSearchExtractedResults": true,
			"cachedInferences":                map[string]interface{}{},
			"annotationInferences":            map[string]interface{}{},
			"emitInferences":                  false,
		},
	}

	resp, err := notionStreamRequest(r.Context(), acc, payload)
	if err != nil {
		log.Printf("[HEAVY] Notion API error: %v", err)
		writeError(w, 502, fmt.Sprintf("Notion API error: %v", err))
		return
	}
	defer resp.Body.Close()

	// Set conversation ID header
	w.Header().Set("X-Conversation-Id", convID)

	if req.Stream {
		handleHeavyStreamResponse(w, r.Context(), resp.Body, chatID, req.Model, convID)
	} else {
		handleHeavyNonStreamResponse(w, resp.Body, chatID, req.Model, convID)
	}
}

// handleHeavyStreamResponse streams and saves assistant response
func handleHeavyStreamResponse(w http.ResponseWriter, ctx context.Context, body io.Reader, chatID, model, convID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 256*1024), 1024*1024)

	first := true
	totalText := ""
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		text, done, _ := extractTextFromNDJSON(line)
		if text == "" && !done {
			continue
		}
		if done && text != "" {
			totalText += text
			if first {
				roleChunk := ChatCompletionResponse{
					ID: chatID, Object: "chat.completion.chunk", Created: time.Now().Unix(), Model: model,
					Choices: []ChatCompletionChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}},
				}
				fmt.Fprintf(w, "data: %s\n\n", mustJSON(roleChunk))
				flusher.Flush()
				first = false
			}
			chunk := ChatCompletionResponse{
				ID: chatID, Object: "chat.completion.chunk", Created: time.Now().Unix(), Model: model,
				Choices: []ChatCompletionChoice{{Index: 0, Delta: &ChatMessage{Content: contentRaw(cleanNotionMarkup(text))}}},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(chunk))
			flusher.Flush()
			break
		}
		if done {
			break
		}

		totalText += text

		if first {
			roleChunk := ChatCompletionResponse{
				ID:      chatID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   model,
				Choices: []ChatCompletionChoice{{
					Index: 0,
					Delta: &ChatMessage{Role: "assistant"},
				}},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(roleChunk))
			flusher.Flush()
			first = false
		}

		chunk := ChatCompletionResponse{
			ID:      chatID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []ChatCompletionChoice{{
				Index: 0,
				Delta: &ChatMessage{Content: contentRaw(cleanNotionMarkup(text))},
			}},
		}
		fmt.Fprintf(w, "data: %s\n\n", mustJSON(chunk))
		flusher.Flush()
	}

	log.Printf("[HEAVY] Stream completed: %d chars total", len(totalText))

	// Save assistant response to DB
	if totalText != "" {
		convManager.SaveMessage(convID, "assistant", totalText, "")
		roundIdx := convManager.GetNextRoundIndex(convID)
		// Get last user message content for sliding window
		msgs := convManager.GetMessages(convID, 2)
		userContent := ""
		for _, m := range msgs {
			if m.Role == "user" {
				userContent = m.Content
			}
		}
		convManager.SaveSlidingWindowRound(convID, roundIdx, userContent, totalText, "")
		convManager.IncrementRoundIndex(convID)
		// Compress old messages beyond sliding window
		convManager.CompressOldMessages(convID)
	}

	sendFinalChunk(w, flusher, chatID, model)
}

// handleHeavyNonStreamResponse collects all and saves
func handleHeavyNonStreamResponse(w http.ResponseWriter, body io.Reader, chatID, model, convID string) {
	var patchResult strings.Builder
	var markdownResult strings.Builder
	var recordMapText string
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 256*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		text, done, source := extractTextFromNDJSON(line)
		if text != "" {
			switch source {
			case "markdown-chat":
				markdownResult.WriteString(text)
			case "patch", "error":
				patchResult.WriteString(text)
			}
		}

		// Capture record-map as fallback if incremental sources produce nothing
		if patchResult.Len() == 0 && markdownResult.Len() == 0 {
			var obj map[string]interface{}
			if json.Unmarshal([]byte(line), &obj) == nil {
				if strings.ToLower(fmt.Sprintf("%v", obj["type"])) == "record-map" {
					rmText := extractFromRecordMap(obj)
					if rmText != "" && len(rmText) > len(recordMapText) {
						recordMapText = cleanNotionMarkup(rmText)
					}
				}
			}
		}

		if done {
			break
		}
	}

	// Pick one source to prevent interleaving: markdown-chat > patch > record-map fallback.
	totalText := markdownResult.String()
	if totalText == "" {
		totalText = patchResult.String()
	}
	if totalText == "" && recordMapText != "" {
		totalText = recordMapText
		log.Printf("[HEAVY] Used record-map fallback: %d chars", len(totalText))
	}

	// Save assistant response to DB
	if totalText != "" {
		convManager.SaveMessage(convID, "assistant", totalText, "")
		roundIdx := convManager.GetNextRoundIndex(convID)
		msgs := convManager.GetMessages(convID, 2)
		userContent := ""
		for _, m := range msgs {
			if m.Role == "user" {
				userContent = m.Content
			}
		}
		convManager.SaveSlidingWindowRound(convID, roundIdx, userContent, totalText, "")
		convManager.IncrementRoundIndex(convID)
		convManager.CompressOldMessages(convID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ChatCompletionResponse{
		ID:      chatID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []ChatCompletionChoice{{
			Index:   0,
			Message: &ChatMessage{Role: "assistant", Content: contentRaw(cleanResponseText(totalText))},
		}},
		Usage:             &UsageInfo{PromptTokens: 0, CompletionTokens: 0, TotalTokens: 0},
		SystemFingerprint: "fp_gotionapi",
	})
}

// ============================================================
// Stream response (SSE → OpenAI format)
// ============================================================

func handleStreamResponse(w http.ResponseWriter, ctx context.Context, body io.Reader, chatID, model string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 256*1024), 1024*1024)

	first := true
	totalText := ""
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		text, done, _ := extractTextFromNDJSON(line)
		if text == "" && !done {
			continue
		}
		if done && text != "" {
			totalText += text
			if first {
				roleChunk := ChatCompletionResponse{
					ID: chatID, Object: "chat.completion.chunk", Created: time.Now().Unix(), Model: model,
					Choices: []ChatCompletionChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}},
				}
				fmt.Fprintf(w, "data: %s\n\n", mustJSON(roleChunk))
				flusher.Flush()
				first = false
			}
			chunk := ChatCompletionResponse{
				ID: chatID, Object: "chat.completion.chunk", Created: time.Now().Unix(), Model: model,
				Choices: []ChatCompletionChoice{{Index: 0, Delta: &ChatMessage{Content: contentRaw(cleanNotionMarkup(text))}}},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(chunk))
			flusher.Flush()
			break
		}
		if done {
			break
		}

		totalText += text

		if first {
			roleChunk := ChatCompletionResponse{
				ID:      chatID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   model,
				Choices: []ChatCompletionChoice{{
					Index: 0,
					Delta: &ChatMessage{Role: "assistant"},
				}},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(roleChunk))
			flusher.Flush()
			first = false
		}

		chunk := ChatCompletionResponse{
			ID:      chatID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []ChatCompletionChoice{{
				Index: 0,
				Delta: &ChatMessage{Content: contentRaw(cleanNotionMarkup(text))},
			}},
		}
		fmt.Fprintf(w, "data: %s\n\n", mustJSON(chunk))
		flusher.Flush()
	}

	log.Printf("Stream completed: %d chars total", len(totalText))

	sendFinalChunk(w, flusher, chatID, model)
}

func sendFinalChunk(w http.ResponseWriter, flusher http.Flusher, chatID, model string) {
	finalChunk := ChatCompletionResponse{
		ID:      chatID,
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []ChatCompletionChoice{{
			Index:        0,
			Delta:        &ChatMessage{},
			FinishReason: strPtr("stop"),
		}},
	}
	fmt.Fprintf(w, "data: %s\n\n", mustJSON(finalChunk))
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// ============================================================
// Non-stream response (collect all → return)
// ============================================================

func handleNonStreamResponse(w http.ResponseWriter, body io.Reader, chatID, model string) {
	var patchResult strings.Builder
	var markdownResult strings.Builder
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 256*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		text, done, source := extractTextFromNDJSON(line)
		if text != "" {
			switch source {
			case "markdown-chat":
				markdownResult.WriteString(text)
			case "patch", "error":
				patchResult.WriteString(text)
			}
		}
		if done {
			break
		}
	}

	totalText := markdownResult.String()
	if totalText == "" {
		totalText = patchResult.String()
	}
	log.Printf("Non-stream completed: %d chars total", len(totalText))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ChatCompletionResponse{
		ID:      chatID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []ChatCompletionChoice{{
			Index:   0,
			Message: &ChatMessage{Role: "assistant", Content: contentRaw(cleanResponseText(totalText))},
		}},
		Usage:             &UsageInfo{PromptTokens: 0, CompletionTokens: 0, TotalTokens: 0},
		SystemFingerprint: "fp_gotionapi",
	})
}

// ============================================================
// Main
// ============================================================

func main() {
	loadDotEnv()    // Load .env file before anything else
	initDebugMode() // Re-evaluate debug mode after .env

	// CLI commands
	if len(os.Args) > 1 {
		cmd := os.Args[1]
		switch cmd {
		case "apikey-reset", "apikey-regenerate":
			loadAccounts()
			regenerateAPIKey()
			fmt.Println("🔑 New API Key:", apiKey)
			fmt.Printf("   Saved to %s\n", apiKeyFile)
			return
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
			fmt.Fprintf(os.Stderr, "Available commands: apikey-reset, apikey-regenerate\n")
			os.Exit(1)
		}
	}

	// APP_MODE: lite, standard, heavy (default: heavy)
	appMode = strings.ToLower(os.Getenv("APP_MODE"))
	if appMode == "" {
		appMode = "heavy"
	}
	if appMode != "lite" && appMode != "standard" && appMode != "heavy" {
		log.Printf("Unknown APP_MODE=%q, falling back to 'heavy'", appMode)
		appMode = "heavy"
	}

	// Initialize TLS-aware HTTP client
	httpClient = createHTTPClient()
	log.Println("HTTP client initialized with TLS fingerprinting (Chrome impersonation)")

	if !loadAccounts() {
		promptAccounts()
	}

	loadAPIKey()

	// Initialize SQLite for heavy mode
	if appMode == "heavy" {
		dbPath := os.Getenv("DB_PATH")
		if dbPath == "" {
			dbPath = "./data/conversations.db"
		}
		var err error
		convManager, err = NewConversationManager(dbPath)
		if err != nil {
			log.Fatalf("Failed to initialize conversation manager: %v", err)
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/v1/models", requireAuth(handleModels))
	http.HandleFunc("/v1/chat/completions", requireAuth(handleChatCompletions))

	log.Printf("🚀 GoTionAPI v3.1.0 starting on :%s", port)
	log.Printf("📋 Models: %d registered", len(modelMap))
	log.Printf("👤 Accounts: %d loaded", len(accounts))
	log.Printf("🔑 Default model: %s", defaultModel)
	log.Printf("⚙️  APP_MODE: %s", appMode)
	if apiKey != "" {
		log.Printf("🔐 API Key: %s (Bearer auth enabled)", apiKey)
	} else {
		log.Printf("🔓 API Key: not set (auth disabled)")
	}
	if debugMode {
		log.Printf("🐛 Debug mode ON (NOTION2API_DEBUG=1)")
	}

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
