package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ============================================================================
// NEXUS//GATE — Minimalist Local Multi-Protocol Agent Gateway & Failover Proxy
// Single-File Zero-Bloat Production Implementation (Go 1.22+ Standard Library)
// ============================================================================

const (
	GatewayVersion     = "1.4.0"
	DefaultConfigPath  = "config.json"
	AnthropicAPIVer    = "2023-06-01"
	DefaultMaxTokens   = 4096
	MaxErrorBodyBytes  = 8192
	ScannerMaxCapacity = 4 * 1024 * 1024 // 4MB max single SSE/NDJSON line buffer
)

// ANSI Terminal Colors for HUD Logging
const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
)

// ============================================================================
// 1. CONFIGURATION & ROUTING STRUCTURES
// ============================================================================

type ProtocolType string

const (
	ProtocolOpenAI    ProtocolType = "openai"    // Upstream A: Native OpenAI / DeepSeek / OpenAI-compatible
	ProtocolGemini    ProtocolType = "gemini"    // Upstream B: Google Gemini API (generateContent / streamGenerateContent?alt=sse)
	ProtocolAnthropic ProtocolType = "anthropic" // Upstream C: Anthropic Claude API (/v1/messages)
	ProtocolOllama    ProtocolType = "ollama"    // Upstream D: Local Ollama (/api/chat)
)

type Config struct {
	ListenAddr        string                    `json:"listen_addr"`
	RequestTimeoutSec int                       `json:"request_timeout_sec"`
	MaxRetriesPerHop  int                       `json:"max_retries_per_hop"`
	RetryBackoffMs    int                       `json:"retry_backoff_ms"`
	GatewayAPIKey     string                    `json:"gateway_api_key,omitempty"`
	Providers         map[string]ProviderConfig `json:"providers"`
	ModelRoutes       map[string][]RouteTarget  `json:"model_routes"`
}

type ProviderConfig struct {
	Protocol      ProtocolType      `json:"protocol"`
	BaseURL       string            `json:"base_url"`
	APIKeys       []string          `json:"api_keys"`
	TimeoutSec    int               `json:"timeout_sec,omitempty"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
}

type RouteTarget struct {
	Provider    string   `json:"provider"`
	TargetModel string   `json:"target_model"`
	Weight      int      `json:"weight,omitempty"`
	APIKeys     []string `json:"api_keys,omitempty"` // Optional per-route key override
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:        "127.0.0.1:8080",
		RequestTimeoutSec: 120,
		MaxRetriesPerHop:  2,
		RetryBackoffMs:    150,
		GatewayAPIKey:     "",
		Providers: map[string]ProviderConfig{
			"openai": {
				Protocol: ProtocolOpenAI,
				BaseURL:  "https://api.openai.com",
				APIKeys: []string{
					osOrDefault("OPENAI_API_KEY", "sk-openai-primary-key"),
					osOrDefault("OPENAI_API_KEY_BACKUP", "sk-openai-secondary-key"),
				},
				TimeoutSec: 90,
			},
			"deepseek": {
				Protocol: ProtocolOpenAI,
				BaseURL:  "https://api.deepseek.com",
				APIKeys: []string{
					osOrDefault("DEEPSEEK_API_KEY", "sk-deepseek-primary-key"),
				},
				TimeoutSec: 90,
			},
			"gemini": {
				Protocol: ProtocolGemini,
				BaseURL:  "https://generativelanguage.googleapis.com",
				APIKeys: []string{
					osOrDefault("GEMINI_API_KEY", "AIzaSy-gemini-primary-key"),
					osOrDefault("GEMINI_API_KEY_BACKUP", "AIzaSy-gemini-secondary-key"),
				},
				TimeoutSec: 90,
			},
			"anthropic": {
				Protocol: ProtocolAnthropic,
				BaseURL:  "https://api.anthropic.com",
				APIKeys: []string{
					osOrDefault("ANTHROPIC_API_KEY", "sk-ant-primary-key"),
				},
				TimeoutSec: 90,
			},
			"ollama": {
				Protocol:   ProtocolOllama,
				BaseURL:    osOrDefault("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
				APIKeys:    []string{""},
				TimeoutSec: 180,
			},
		},
		ModelRoutes: map[string][]RouteTarget{
			"gpt-4o": {
				{Provider: "openai", TargetModel: "gpt-4o"},
				{Provider: "anthropic", TargetModel: "claude-3-5-sonnet-20241022"},
				{Provider: "gemini", TargetModel: "gemini-1.5-pro"},
				{Provider: "ollama", TargetModel: "llama3.1:latest"},
			},
			"gpt-4o-mini": {
				{Provider: "openai", TargetModel: "gpt-4o-mini"},
				{Provider: "gemini", TargetModel: "gemini-1.5-flash"},
				{Provider: "ollama", TargetModel: "llama3.2:latest"},
			},
			"claude-3-5-sonnet": {
				{Provider: "anthropic", TargetModel: "claude-3-5-sonnet-20241022"},
				{Provider: "openai", TargetModel: "gpt-4o"},
				{Provider: "gemini", TargetModel: "gemini-1.5-pro"},
			},
			"deepseek-chat": {
				{Provider: "deepseek", TargetModel: "deepseek-chat"},
				{Provider: "openai", TargetModel: "gpt-4o"},
				{Provider: "ollama", TargetModel: "qwen2.5-coder:latest"},
			},
			"gemini-1.5-pro": {
				{Provider: "gemini", TargetModel: "gemini-1.5-pro"},
				{Provider: "openai", TargetModel: "gpt-4o"},
			},
			"local-agent": {
				{Provider: "ollama", TargetModel: "llama3.1:latest"},
				{Provider: "deepseek", TargetModel: "deepseek-chat"},
			},
			"default": {
				{Provider: "openai", TargetModel: "gpt-4o-mini"},
				{Provider: "gemini", TargetModel: "gemini-1.5-flash"},
				{Provider: "ollama", TargetModel: "llama3.1:latest"},
			},
		},
	}
}

func osOrDefault(envKey, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	return fallback
}

func LoadOrCreateConfig(path string) (*Config, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg := DefaultConfig()
			raw, mErr := json.MarshalIndent(cfg, "", "  ")
			if mErr != nil {
				return nil, false, fmt.Errorf("marshal default config: %w", mErr)
			}
			if wErr := os.WriteFile(path, raw, 0600); wErr != nil {
				return nil, false, fmt.Errorf("write default config %s: %w", path, wErr)
			}
			return cfg, true, nil
		}
		return nil, false, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, false, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:8080"
	}
	if cfg.RequestTimeoutSec <= 0 {
		cfg.RequestTimeoutSec = 120
	}
	if cfg.MaxRetriesPerHop <= 0 {
		cfg.MaxRetriesPerHop = 1
	}
	if cfg.RetryBackoffMs < 0 {
		cfg.RetryBackoffMs = 100
	}
	if cfg.Providers == nil {
		cfg.Providers = make(map[string]ProviderConfig)
	}
	if cfg.ModelRoutes == nil {
		cfg.ModelRoutes = make(map[string][]RouteTarget)
	}
	return &cfg, false, nil
}

// ============================================================================
// 2. UNIFIED INBOUND OPENAI DATA MODELS
// ============================================================================

type OpenAIChatRequest struct {
	Model            string          `json:"model"`
	Messages         []OpenAIMessage `json:"messages"`
	Stream           bool            `json:"stream,omitempty"`
	Temperature      *float64        `json:"temperature,omitempty"`
	TopP             *float64        `json:"top_p,omitempty"`
	MaxTokens        *int            `json:"max_tokens,omitempty"`
	MaxCompletionTok *int            `json:"max_completion_tokens,omitempty"`
	Stop             any             `json:"stop,omitempty"`
	PresencePenalty  *float64        `json:"presence_penalty,omitempty"`
	FrequencyPenalty *float64        `json:"frequency_penalty,omitempty"`
	User             string          `json:"user,omitempty"`
}

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
	Name    string `json:"name,omitempty"`
}

// ExtractText cleanly normalizes string content or OpenAI multi-part content arrays into a single text string.
func (m *OpenAIMessage) ExtractText() string {
	switch v := m.Content.(type) {
	case string:
		return v
	case []any:
		var sb strings.Builder
		for _, part := range v {
			if partMap, ok := part.(map[string]any); ok {
				if pType, _ := partMap["type"].(string); pType == "text" || pType == "" {
					if txt, ok := partMap["text"].(string); ok {
						if sb.Len() > 0 {
							sb.WriteString("\n")
						}
						sb.WriteString(txt)
					}
				}
			} else if str, ok := part.(string); ok {
				sb.WriteString(str)
			}
		}
		return sb.String()
	default:
		if v == nil {
			return ""
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(raw)
	}
}

func (r *OpenAIChatRequest) EffectiveMaxTokens() int {
	if r.MaxCompletionTok != nil && *r.MaxCompletionTok > 0 {
		return *r.MaxCompletionTok
	}
	if r.MaxTokens != nil && *r.MaxTokens > 0 {
		return *r.MaxTokens
	}
	return DefaultMaxTokens
}

func (r *OpenAIChatRequest) ExtractStopSequences() []string {
	if r.Stop == nil {
		return nil
	}
	switch v := r.Stop.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

type OpenAIChatResponse struct {
	ID                string         `json:"id"`
	Object            string         `json:"object"`
	Created           int64          `json:"created"`
	Model             string         `json:"model"`
	SystemFingerprint string         `json:"system_fingerprint,omitempty"`
	Choices           []OpenAIChoice `json:"choices"`
	Usage             *OpenAIUsage   `json:"usage,omitempty"`
}

type OpenAIChoice struct {
	Index        int              `json:"index"`
	Message      *OpenAIRespMsg   `json:"message,omitempty"`
	Delta        *OpenAIDeltaMsg  `json:"delta,omitempty"`
	FinishReason *string          `json:"finish_reason"`
}

type OpenAIRespMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIDeltaMsg struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type OpenAIModelList struct {
	Object string            `json:"object"`
	Data   []OpenAIModelItem `json:"data"`
}

type OpenAIModelItem struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type OpenAIErrorResponse struct {
	Error OpenAIErrorDetail `json:"error"`
}

type OpenAIErrorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Param   string `json:"param,omitempty"`
	Code    string `json:"code,omitempty"`
}

// ============================================================================
// 3. UPSTREAM B: GOOGLE GEMINI PROTOCOL STRUCTURES & TRANSPILER
// ============================================================================

type GeminiRequest struct {
	SystemInstruction *GeminiContent        `json:"systemInstruction,omitempty"`
	Contents          []GeminiContent       `json:"contents"`
	GenerationConfig  *GeminiGenConfig      `json:"generationConfig,omitempty"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiGenConfig struct {
	Temperature     *float64 `json:"temperature,omitempty"`
	TopP            *float64 `json:"topP,omitempty"`
	MaxOutputTokens *int     `json:"maxOutputTokens,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

type GeminiResponse struct {
	Candidates    []GeminiCandidate    `json:"candidates"`
	UsageMetadata *GeminiUsageMetadata `json:"usageMetadata,omitempty"`
}

type GeminiCandidate struct {
	Content      GeminiContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"`
	Index        int           `json:"index"`
}

type GeminiUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

func TranslateOpenAIToGemini(req *OpenAIChatRequest) (*GeminiRequest, error) {
	gReq := &GeminiRequest{
		Contents: make([]GeminiContent, 0, len(req.Messages)),
	}

	var sysParts []GeminiPart
	for _, msg := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		text := msg.ExtractText()
		if role == "system" || role == "developer" {
			if text != "" {
				sysParts = append(sysParts, GeminiPart{Text: text})
			}
			continue
		}

		geminiRole := "user"
		if role == "assistant" || role == "model" {
			geminiRole = "model"
		}

		// Merge consecutive turns of the same role to satisfy Gemini's strict turn alternation requirement
		if len(gReq.Contents) > 0 && gReq.Contents[len(gReq.Contents)-1].Role == geminiRole {
			lastIdx := len(gReq.Contents) - 1
			gReq.Contents[lastIdx].Parts = append(gReq.Contents[lastIdx].Parts, GeminiPart{Text: text})
		} else {
			gReq.Contents = append(gReq.Contents, GeminiContent{
				Role:  geminiRole,
				Parts: []GeminiPart{{Text: text}},
			})
		}
	}

	if len(sysParts) > 0 {
		gReq.SystemInstruction = &GeminiContent{
			Parts: sysParts,
		}
	}

	// Ensure at least one user content block exists
	if len(gReq.Contents) == 0 {
		gReq.Contents = append(gReq.Contents, GeminiContent{
			Role:  "user",
			Parts: []GeminiPart{{Text: "Hello"}},
		})
	}

	stops := req.ExtractStopSequences()
	maxTok := req.MaxTokens
	if req.MaxCompletionTok != nil {
		maxTok = req.MaxCompletionTok
	}
	if req.Temperature != nil || req.TopP != nil || maxTok != nil || len(stops) > 0 {
		gReq.GenerationConfig = &GeminiGenConfig{
			Temperature:     req.Temperature,
			TopP:            req.TopP,
			MaxOutputTokens: maxTok,
			StopSequences:   stops,
		}
	}

	return gReq, nil
}

func mapGeminiFinishReason(reason string) string {
	switch strings.ToUpper(reason) {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT":
		return "content_filter"
	default:
		return "stop"
	}
}

func TranslateGeminiToOpenAI(gResp *GeminiResponse, requestedModel string) *OpenAIChatResponse {
	var textBuilder strings.Builder
	finishReason := "stop"

	if len(gResp.Candidates) > 0 {
		cand := gResp.Candidates[0]
		for _, p := range cand.Content.Parts {
			textBuilder.WriteString(p.Text)
		}
		if cand.FinishReason != "" {
			finishReason = mapGeminiFinishReason(cand.FinishReason)
		}
	}

	content := textBuilder.String()
	usage := &OpenAIUsage{
		PromptTokens:     estimateTokens(content) / 2,
		CompletionTokens: estimateTokens(content),
	}
	usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens

	if gResp.UsageMetadata != nil {
		usage.PromptTokens = gResp.UsageMetadata.PromptTokenCount
		usage.CompletionTokens = gResp.UsageMetadata.CandidatesTokenCount
		usage.TotalTokens = gResp.UsageMetadata.TotalTokenCount
		if usage.TotalTokens == 0 {
			usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
		}
	}

	return &OpenAIChatResponse{
		ID:      "chatcmpl-" + randomHex(12),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   requestedModel,
		Choices: []OpenAIChoice{
			{
				Index: 0,
				Message: &OpenAIRespMsg{
					Role:    "assistant",
					Content: content,
				},
				FinishReason: &finishReason,
			},
		},
		Usage: usage,
	}
}

// ============================================================================
// 4. UPSTREAM C: ANTHROPIC CLAUDE PROTOCOL STRUCTURES & TRANSPILER
// ============================================================================

type AnthropicRequest struct {
	Model         string             `json:"model"`
	Messages      []AnthropicMessage `json:"messages"`
	System        string             `json:"system,omitempty"`
	MaxTokens     int                `json:"max_tokens"`
	Stream        bool               `json:"stream,omitempty"`
	Temperature   *float64           `json:"temperature,omitempty"`
	TopP          *float64           `json:"top_p,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
}

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AnthropicResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Content      []AnthropicContentBlock `json:"content"`
	Model        string                  `json:"model"`
	StopReason   string                  `json:"stop_reason"`
	Usage        *AnthropicUsage         `json:"usage,omitempty"`
}

type AnthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type AnthropicStreamEvent struct {
	Type         string                 `json:"type"`
	Message      *AnthropicResponse     `json:"message,omitempty"`
	Index        int                    `json:"index,omitempty"`
	ContentBlock *AnthropicContentBlock `json:"content_block,omitempty"`
	Delta        *AnthropicStreamDelta  `json:"delta,omitempty"`
	Usage        *AnthropicUsage        `json:"usage,omitempty"`
}

type AnthropicStreamDelta struct {
	Type       string `json:"type,omitempty"`
	Text       string `json:"text,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
}

func TranslateOpenAIToAnthropic(req *OpenAIChatRequest, targetModel string) (*AnthropicRequest, error) {
	aReq := &AnthropicRequest{
		Model:         targetModel,
		Messages:      make([]AnthropicMessage, 0, len(req.Messages)),
		MaxTokens:     req.EffectiveMaxTokens(),
		Stream:        req.Stream,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		StopSequences: req.ExtractStopSequences(),
	}

	var sysPrompts []string
	for _, msg := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		text := msg.ExtractText()
		if role == "system" || role == "developer" {
			if text != "" {
				sysPrompts = append(sysPrompts, text)
			}
			continue
		}

		antRole := "user"
		if role == "assistant" {
			antRole = "assistant"
		}

		// Merge consecutive identical roles for Anthropic compliance
		if len(aReq.Messages) > 0 && aReq.Messages[len(aReq.Messages)-1].Role == antRole {
			lastIdx := len(aReq.Messages) - 1
			aReq.Messages[lastIdx].Content += "\n\n" + text
		} else {
			aReq.Messages = append(aReq.Messages, AnthropicMessage{
				Role:    antRole,
				Content: text,
			})
		}
	}

	if len(sysPrompts) > 0 {
		aReq.System = strings.Join(sysPrompts, "\n\n")
	}

	// Anthropic requires the first message to use the "user" role
	if len(aReq.Messages) == 0 {
		aReq.Messages = append(aReq.Messages, AnthropicMessage{
			Role:    "user",
			Content: "Hello",
		})
	} else if aReq.Messages[0].Role != "user" {
		aReq.Messages = append([]AnthropicMessage{{Role: "user", Content: "(Continue)"}}, aReq.Messages...)
	}

	return aReq, nil
}

func mapAnthropicStopReason(reason string) string {
	switch reason {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	default:
		return "stop"
	}
}

func TranslateAnthropicToOpenAI(aResp *AnthropicResponse, requestedModel string) *OpenAIChatResponse {
	var sb strings.Builder
	for _, blk := range aResp.Content {
		if blk.Type == "text" || blk.Type == "" {
			sb.WriteString(blk.Text)
		}
	}
	content := sb.String()
	finishReason := mapAnthropicStopReason(aResp.StopReason)

	usage := &OpenAIUsage{
		PromptTokens:     estimateTokens(content) / 2,
		CompletionTokens: estimateTokens(content),
	}
	if aResp.Usage != nil {
		usage.PromptTokens = aResp.Usage.InputTokens
		usage.CompletionTokens = aResp.Usage.OutputTokens
	}
	usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens

	id := aResp.ID
	if id == "" {
		id = "chatcmpl-" + randomHex(12)
	} else if !strings.HasPrefix(id, "chatcmpl-") {
		id = "chatcmpl-" + id
	}

	return &OpenAIChatResponse{
		ID:      id,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   requestedModel,
		Choices: []OpenAIChoice{
			{
				Index: 0,
				Message: &OpenAIRespMsg{
					Role:    "assistant",
					Content: content,
				},
				FinishReason: &finishReason,
			},
		},
		Usage: usage,
	}
}

// ============================================================================
// 5. UPSTREAM D: LOCAL OLLAMA PROTOCOL STRUCTURES & TRANSPILER
// ============================================================================

type OllamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []OllamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  map[string]any  `json:"options,omitempty"`
}

type OllamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OllamaChatResponse struct {
	Model           string        `json:"model"`
	CreatedAt       string        `json:"created_at"`
	Message         OllamaMessage `json:"message"`
	Done            bool          `json:"done"`
	DoneReason      string        `json:"done_reason,omitempty"`
	PromptEvalCount int           `json:"prompt_eval_count,omitempty"`
	EvalCount       int           `json:"eval_count,omitempty"`
}

func TranslateOpenAIToOllama(req *OpenAIChatRequest, targetModel string) *OllamaChatRequest {
	oReq := &OllamaChatRequest{
		Model:    targetModel,
		Messages: make([]OllamaMessage, 0, len(req.Messages)),
		Stream:   req.Stream,
	}

	for _, msg := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		if role == "developer" {
			role = "system"
		}
		oReq.Messages = append(oReq.Messages, OllamaMessage{
			Role:    role,
			Content: msg.ExtractText(),
		})
	}

	opts := make(map[string]any)
	if req.Temperature != nil {
		opts["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		opts["top_p"] = *req.TopP
	}
	if req.MaxTokens != nil {
		opts["num_predict"] = *req.MaxTokens
	} else if req.MaxCompletionTok != nil {
		opts["num_predict"] = *req.MaxCompletionTok
	}
	if stops := req.ExtractStopSequences(); len(stops) > 0 {
		opts["stop"] = stops
	}
	if len(opts) > 0 {
		oReq.Options = opts
	}

	return oReq
}

func TranslateOllamaToOpenAI(oResp *OllamaChatResponse, requestedModel string) *OpenAIChatResponse {
	finishReason := "stop"
	if oResp.DoneReason == "length" {
		finishReason = "length"
	}

	pTok := oResp.PromptEvalCount
	cTok := oResp.EvalCount
	if cTok == 0 {
		cTok = estimateTokens(oResp.Message.Content)
	}
	if pTok == 0 {
		pTok = cTok / 2
	}

	return &OpenAIChatResponse{
		ID:      "chatcmpl-" + randomHex(12),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   requestedModel,
		Choices: []OpenAIChoice{
			{
				Index: 0,
				Message: &OpenAIRespMsg{
					Role:    "assistant",
					Content: oResp.Message.Content,
				},
				FinishReason: &finishReason,
			},
		},
		Usage: &OpenAIUsage{
			PromptTokens:     pTok,
			CompletionTokens: cTok,
			TotalTokens:      pTok + cTok,
		},
	}
}

// ============================================================================
// 6. TELEMETRY, IN-MEMORY METRICS & TERMINAL HUD
// ============================================================================

type Telemetry struct {
	startTime            time.Time
	totalRequests        atomic.Uint64
	successfulRequests   atomic.Uint64
	failedRequests       atomic.Uint64
	failoverHopsTotal    atomic.Uint64
	estimatedTokensTotal atomic.Uint64
	activeStreams        atomic.Int64
	providerHits         sync.Map // map[string]*atomic.Uint64
}

func NewTelemetry() *Telemetry {
	return &Telemetry{
		startTime: time.Now(),
	}
}

func (t *Telemetry) RecordProviderHit(provider string) {
	val, ok := t.providerHits.Load(provider)
	if !ok {
		counter := &atomic.Uint64{}
		actual, _ := t.providerHits.LoadOrStore(provider, counter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

type RequestAudit struct {
	Timestamp        time.Time
	ClientIP         string
	RequestedModel   string
	TargetModel      string
	UpstreamProvider string
	Protocol         ProtocolType
	Stream           bool
	StatusCode       int
	Latency          time.Duration
	FailoverHops     int
	EstimatedTokens  int
	ErrorDetail      string
}

func LogHUD(audit RequestAudit) {
	ts := audit.Timestamp.Format("2006-01-02 15:04:05.000")

	statusColor := ansiGreen
	if audit.StatusCode >= 500 {
		statusColor = ansiRed
	} else if audit.StatusCode >= 400 {
		statusColor = ansiYellow
	}

	hopColor := ansiDim
	if audit.FailoverHops > 0 {
		hopColor = ansiYellow
	}

	modeTag := "JSON"
	if audit.Stream {
		modeTag = "SSE "
	}

	providerTag := audit.UpstreamProvider
	if providerTag == "" {
		providerTag = "none"
	}
	if audit.TargetModel != "" && audit.TargetModel != audit.RequestedModel {
		providerTag = fmt.Sprintf("%s:%s", audit.UpstreamProvider, audit.TargetModel)
	}

	fmt.Printf("%s[%s]%s %sNEXUS//GATE%s │ IP:%-15s │ Model:%-18s │ Upstream:%-24s │ Mode:%s │ Latency:%6dms │ Status:%s%3d%s │ Hops:%s%d%s │ ~Tok:%d\n",
		ansiDim, ts, ansiReset,
		ansiBold+ansiCyan, ansiReset,
		truncateStr(audit.ClientIP, 15),
		truncateStr(audit.RequestedModel, 18),
		truncateStr(providerTag, 24),
		modeTag,
		audit.Latency.Milliseconds(),
		statusColor, audit.StatusCode, ansiReset,
		hopColor, audit.FailoverHops, ansiReset,
		audit.EstimatedTokens,
	)
}

// ============================================================================
// 7. GATEWAY ENGINE, MULTI-KEY LOAD BALANCER & FAILOVER CONTROLLER
// ============================================================================

type Gateway struct {
	cfg        *Config
	cfgMu      sync.RWMutex
	httpClient *http.Client
	telemetry  *Telemetry
	keyCursor  sync.Map // map[string]*atomic.Uint64 -> per-provider round-robin key index
}

func NewGateway(cfg *Config) *Gateway {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.RequestTimeoutSec) * time.Second,
	}

	return &Gateway{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: transport,
		},
		telemetry: NewTelemetry(),
	}
}

// NextKeyIndex atomically increments and returns the starting index for a provider's API key pool.
func (g *Gateway) NextKeyIndex(providerName string, keyCount int) int {
	if keyCount <= 1 {
		return 0
	}
	val, ok := g.keyCursor.Load(providerName)
	if !ok {
		c := &atomic.Uint64{}
		actual, _ := g.keyCursor.LoadOrStore(providerName, c)
		val = actual
	}
	idx := val.(*atomic.Uint64).Add(1) - 1
	return int(idx % uint64(keyCount))
}

// ResolveRouteChain maps an incoming model alias to an ordered slice of failover targets.
// Supports:
//   1. Exact match in `model_routes` (e.g., "gpt-4o" -> [openai, anthropic, gemini, ollama])
//   2. Explicit "provider/model" prefix syntax (e.g., "gemini/gemini-1.5-pro")
//   3. Heuristic provider inference + "default" fallback chain
func (g *Gateway) ResolveRouteChain(requestedModel string) []RouteTarget {
	g.cfgMu.RLock()
	defer g.cfgMu.RUnlock()

	model := strings.TrimSpace(requestedModel)
	if routes, ok := g.cfg.ModelRoutes[model]; ok && len(routes) > 0 {
		return cloneRoutes(routes)
	}

	// Support explicit "provider/model" routing syntax
	if slashIdx := strings.Index(model, "/"); slashIdx > 0 && slashIdx < len(model)-1 {
		prov := model[:slashIdx]
		targetMod := model[slashIdx+1:]
		if _, exists := g.cfg.Providers[prov]; exists {
			chain := []RouteTarget{{Provider: prov, TargetModel: targetMod}}
			if defRoutes, ok := g.cfg.ModelRoutes["default"]; ok {
				chain = append(chain, cloneRoutes(defRoutes)...)
			}
			return chain
		}
	}

	// Prefix heuristic + default fallback chain
	var chain []RouteTarget
	lower := strings.ToLower(model)
	switch {
	case strings.HasPrefix(lower, "claude"):
		if _, ok := g.cfg.Providers["anthropic"]; ok {
			chain = append(chain, RouteTarget{Provider: "anthropic", TargetModel: model})
		}
	case strings.HasPrefix(lower, "gemini"):
		if _, ok := g.cfg.Providers["gemini"]; ok {
			chain = append(chain, RouteTarget{Provider: "gemini", TargetModel: model})
		}
	case strings.HasPrefix(lower, "deepseek"):
		if _, ok := g.cfg.Providers["deepseek"]; ok {
			chain = append(chain, RouteTarget{Provider: "deepseek", TargetModel: model})
		}
	case strings.HasPrefix(lower, "gpt-") || strings.HasPrefix(lower, "o1") || strings.HasPrefix(lower, "o3"):
		if _, ok := g.cfg.Providers["openai"]; ok {
			chain = append(chain, RouteTarget{Provider: "openai", TargetModel: model})
		}
	case strings.Contains(lower, ":") || strings.HasPrefix(lower, "llama") || strings.HasPrefix(lower, "qwen") || strings.HasPrefix(lower, "mistral"):
		if _, ok := g.cfg.Providers["ollama"]; ok {
			chain = append(chain, RouteTarget{Provider: "ollama", TargetModel: model})
		}
	}

	if defRoutes, ok := g.cfg.ModelRoutes["default"]; ok {
		for _, r := range defRoutes {
			if len(chain) == 0 || (chain[0].Provider != r.Provider || chain[0].TargetModel != r.TargetModel) {
				chain = append(chain, r)
			}
		}
	}

	return chain
}

func cloneRoutes(in []RouteTarget) []RouteTarget {
	out := make([]RouteTarget, len(in))
	copy(out, in)
	return out
}

// ============================================================================
// 8. HTTP SERVER & INBOUND HANDLERS
// ============================================================================

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set standard permissive CORS headers for local agent & browser UI compatibility
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, Anthropic-Version")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Optional Gateway Authentication Check
	if g.cfg.GatewayAPIKey != "" && r.URL.Path != "/health" {
		if !g.verifyInboundAuth(r) {
			writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing Gateway API key", "authentication_error", "invalid_api_key")
			return
		}
	}

	switch {
	case r.URL.Path == "/health" && r.Method == http.MethodGet:
		g.handleHealth(w, r)
	case r.URL.Path == "/v1/models" && r.Method == http.MethodGet:
		g.handleModels(w, r)
	case r.URL.Path == "/v1/chat/completions" && r.Method == http.MethodPost:
		g.handleChatCompletions(w, r)
	default:
		writeOpenAIError(w, http.StatusNotFound, fmt.Sprintf("Endpoint %s %s not found on NEXUS//GATE", r.Method, r.URL.Path), "invalid_request_error", "endpoint_not_found")
	}
}

func (g *Gateway) verifyInboundAuth(r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token := strings.TrimSpace(auth[7:])
		if token == g.cfg.GatewayAPIKey {
			return true
		}
	}
	if xKey := strings.TrimSpace(r.Header.Get("X-API-Key")); xKey == g.cfg.GatewayAPIKey {
		return true
	}
	return false
}

func (g *Gateway) handleHealth(w http.ResponseWriter, _ *http.Request) {
	providerCounts := make(map[string]uint64)
	g.telemetry.providerHits.Range(func(key, value any) bool {
		providerCounts[key.(string)] = value.(*atomic.Uint64).Load()
		return true
	})

	payload := map[string]any{
		"status":    "ok",
		"gateway":   "NEXUS//GATE",
		"version":   GatewayVersion,
		"uptime_s":  int64(time.Since(g.telemetry.startTime).Seconds()),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"metrics": map[string]any{
			"total_requests":               g.telemetry.totalRequests.Load(),
			"successful_requests":          g.telemetry.successfulRequests.Load(),
			"failed_requests":              g.telemetry.failedRequests.Load(),
			"active_streams":               g.telemetry.activeStreams.Load(),
			"total_failover_hops":          g.telemetry.failoverHopsTotal.Load(),
			"estimated_tokens_transferred": g.telemetry.estimatedTokensTotal.Load(),
			"provider_hits":                providerCounts,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

func (g *Gateway) handleModels(w http.ResponseWriter, _ *http.Request) {
	g.cfgMu.RLock()
	defer g.cfgMu.RUnlock()

	now := time.Now().Unix()
	items := make([]OpenAIModelItem, 0, len(g.cfg.ModelRoutes))
	for alias, targets := range g.cfg.ModelRoutes {
		owner := "nexus-gate"
		if len(targets) > 0 {
			owner = fmt.Sprintf("nexus-gate (%s->%s)", targets[0].Provider, targets[0].TargetModel)
		}
		items = append(items, OpenAIModelItem{
			ID:      alias,
			Object:  "model",
			Created: now,
			OwnedBy: owner,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(OpenAIModelList{
		Object: "list",
		Data:   items,
	})
}

func (g *Gateway) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	g.telemetry.totalRequests.Add(1)
	clientIP := extractClientIP(r)

	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
	if err != nil {
		g.telemetry.failedRequests.Add(1)
		writeOpenAIError(w, http.StatusBadRequest, "Failed to read request body", "invalid_request_error", "read_error")
		return
	}
	defer r.Body.Close()

	var chatReq OpenAIChatRequest
	if err := json.Unmarshal(rawBody, &chatReq); err != nil {
		g.telemetry.failedRequests.Add(1)
		writeOpenAIError(w, http.StatusBadRequest, "Invalid JSON payload: "+err.Error(), "invalid_request_error", "invalid_json")
		return
	}

	if chatReq.Model == "" {
		chatReq.Model = "default"
	}
	if len(chatReq.Messages) == 0 {
		g.telemetry.failedRequests.Add(1)
		writeOpenAIError(w, http.StatusBadRequest, "messages array is required and cannot be empty", "invalid_request_error", "missing_messages")
		return
	}

	promptTokensEst := estimateMessagesTokens(chatReq.Messages)
	routeChain := g.ResolveRouteChain(chatReq.Model)
	if len(routeChain) == 0 {
		g.telemetry.failedRequests.Add(1)
		audit := RequestAudit{
			Timestamp:      startTime,
			ClientIP:       clientIP,
			RequestedModel: chatReq.Model,
			Stream:         chatReq.Stream,
			StatusCode:     http.StatusBadGateway,
			Latency:        time.Since(startTime),
		}
		LogHUD(audit)
		writeOpenAIError(w, http.StatusBadGateway, fmt.Sprintf("No upstream route configured for model '%s'", chatReq.Model), "routing_error", "model_not_routed")
		return
	}

	// Execute Fault-Tolerant Failover Loop across route targets and API keys
	var (
		attemptHops int
		lastErr     error
		lastStatus  = http.StatusBadGateway
	)

	for _, target := range routeChain {
		g.cfgMu.RLock()
		provCfg, exists := g.cfg.Providers[target.Provider]
		g.cfgMu.RUnlock()
		if !exists {
			continue
		}

		keys := target.APIKeys
		if len(keys) == 0 {
			keys = provCfg.APIKeys
		}
		if len(keys) == 0 {
			keys = []string{""}
		}

		startIdx := g.NextKeyIndex(target.Provider, len(keys))
		maxKeyAttempts := len(keys)
		if g.cfg.MaxRetriesPerHop > 0 && maxKeyAttempts < g.cfg.MaxRetriesPerHop {
			maxKeyAttempts = g.cfg.MaxRetriesPerHop
		}

		for kAttempt := 0; kAttempt < maxKeyAttempts; kAttempt++ {
			apiKey := keys[(startIdx+kAttempt)%len(keys)]

			timeoutSec := provCfg.TimeoutSec
			if timeoutSec <= 0 {
				timeoutSec = g.cfg.RequestTimeoutSec
			}
			attemptCtx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSec)*time.Second)

			upstreamReq, uErr := g.buildUpstreamHTTPRequest(attemptCtx, &provCfg, target.TargetModel, apiKey, &chatReq, rawBody)
			if uErr != nil {
				cancel()
				lastErr = uErr
				attemptHops++
				continue
			}

			resp, doErr := g.httpClient.Do(upstreamReq)
			if doErr != nil {
				cancel()
				lastErr = fmt.Errorf("provider %s network/timeout error: %w", target.Provider, doErr)
				lastStatus = http.StatusGatewayTimeout
				// If the client itself disconnected, abort immediately without retrying
				if errors.Is(r.Context().Err(), context.Canceled) {
					g.telemetry.failedRequests.Add(1)
					return
				}
				attemptHops++
				g.sleepBackoff(r.Context())
				continue
			}

			// Evaluate Upstream HTTP Status Code for Failover Eligibility
			if shouldFailoverStatus(resp.StatusCode) {
				errSnippet, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
				_ = resp.Body.Close()
				cancel()

				lastStatus = resp.StatusCode
				lastErr = fmt.Errorf("provider %s (model %s) returned HTTP %d: %s",
					target.Provider, target.TargetModel, resp.StatusCode, strings.TrimSpace(string(errSnippet)))
				attemptHops++
				g.sleepBackoff(r.Context())
				continue
			}

			// Non-retriable client error from upstream (e.g., 400 Bad Request) or 200 OK
			if resp.StatusCode >= 400 {
				errSnippet, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
				_ = resp.Body.Close()
				cancel()

				g.telemetry.failedRequests.Add(1)
				g.telemetry.failoverHopsTotal.Add(uint64(attemptHops))
				audit := RequestAudit{
					Timestamp:        startTime,
					ClientIP:         clientIP,
					RequestedModel:   chatReq.Model,
					TargetModel:      target.TargetModel,
					UpstreamProvider: target.Provider,
					Protocol:         provCfg.Protocol,
					Stream:           chatReq.Stream,
					StatusCode:       resp.StatusCode,
					Latency:          time.Since(startTime),
					FailoverHops:     attemptHops,
					EstimatedTokens:  promptTokensEst,
				}
				LogHUD(audit)
				writeOpenAIError(w, resp.StatusCode, fmt.Sprintf("Upstream %s rejected request: %s", target.Provider, strings.TrimSpace(string(errSnippet))), "upstream_error", "upstream_rejected")
				return
			}

			// Upstream responded with 2xx OK! Stream or transpile the response back to client.
			var completionTokens int
			var handleErr error

			if chatReq.Stream {
				g.telemetry.activeStreams.Add(1)
				completionTokens, handleErr = g.streamUpstreamToClient(w, resp.Body, provCfg.Protocol, chatReq.Model)
				g.telemetry.activeStreams.Add(-1)
			} else {
				completionTokens, handleErr = g.transpileJSONToClient(w, resp.Body, provCfg.Protocol, chatReq.Model)
			}

			_ = resp.Body.Close()
			cancel()

			totalTokens := promptTokensEst + completionTokens
			g.telemetry.failoverHopsTotal.Add(uint64(attemptHops))
			g.telemetry.estimatedTokensTotal.Add(uint64(totalTokens))
			g.telemetry.RecordProviderHit(target.Provider)

			statusCode := http.StatusOK
			if handleErr != nil {
				g.telemetry.failedRequests.Add(1)
			} else {
				g.telemetry.successfulRequests.Add(1)
			}

			audit := RequestAudit{
				Timestamp:        startTime,
				ClientIP:         clientIP,
				RequestedModel:   chatReq.Model,
				TargetModel:      target.TargetModel,
				UpstreamProvider: target.Provider,
				Protocol:         provCfg.Protocol,
				Stream:           chatReq.Stream,
				StatusCode:       statusCode,
				Latency:          time.Since(startTime),
				FailoverHops:     attemptHops,
				EstimatedTokens:  totalTokens,
			}
			LogHUD(audit)
			return
		}
	}

	// All failover routes & keys exhausted
	g.telemetry.failedRequests.Add(1)
	g.telemetry.failoverHopsTotal.Add(uint64(attemptHops))

	errMsg := "All configured upstream providers and failover keys exhausted"
	if lastErr != nil {
		errMsg = fmt.Sprintf("%s (last error: %v)", errMsg, lastErr)
	}

	audit := RequestAudit{
		Timestamp:        startTime,
		ClientIP:         clientIP,
		RequestedModel:   chatReq.Model,
		UpstreamProvider: "exhausted",
		Stream:           chatReq.Stream,
		StatusCode:       lastStatus,
		Latency:          time.Since(startTime),
		FailoverHops:     attemptHops,
		EstimatedTokens:  promptTokensEst,
	}
	LogHUD(audit)

	writeOpenAIError(w, lastStatus, errMsg, "failover_exhausted_error", "all_upstreams_failed")
}

// shouldFailoverStatus determines whether an HTTP response code should trigger automatic key/provider failover.
// Covers HTTP 429 (Rate Limit), 401/403 (Invalid/Exhausted Key in pool), 408 (Request Timeout), and 5xx Server Errors.
func shouldFailoverStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429 Rate Limit
		http.StatusUnauthorized,        // 401 Invalid/Revoked Key -> try next key or fallback provider
		http.StatusForbidden,           // 403 Quota/Key Forbidden -> try next key or fallback provider
		http.StatusRequestTimeout,      // 408 Timeout
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504
		529:                            // Anthropic Overloaded
		return true
	default:
		return code >= 500
	}
}

func (g *Gateway) sleepBackoff(ctx context.Context) {
	if g.cfg.RetryBackoffMs <= 0 {
		return
	}
	timer := time.NewTimer(time.Duration(g.cfg.RetryBackoffMs) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// ============================================================================
// 9. UPSTREAM HTTP REQUEST BUILDER (PROTOCOL DISPATCH)
// ============================================================================

func (g *Gateway) buildUpstreamHTTPRequest(
	ctx context.Context,
	prov *ProviderConfig,
	targetModel string,
	apiKey string,
	chatReq *OpenAIChatRequest,
	originalBody []byte,
) (*http.Request, error) {
	baseURL := strings.TrimRight(prov.BaseURL, "/")

	var (
		endpointURL string
		payloadBytes []byte
		err          error
	)

	switch prov.Protocol {
	case ProtocolOpenAI:
		// Upstream A: Native OpenAI / DeepSeek pass-through with model name rewrite & Auth swap
		if strings.HasSuffix(baseURL, "/v1") {
			endpointURL = baseURL + "/chat/completions"
		} else {
			endpointURL = baseURL + "/v1/chat/completions"
		}
		payloadBytes, err = rewriteOpenAIModelInPayload(originalBody, targetModel)
		if err != nil {
			return nil, fmt.Errorf("rewrite openai payload: %w", err)
		}

	case ProtocolGemini:
		// Upstream B: Google Gemini API (generateContent & streamGenerateContent?alt=sse)
		gReq, gErr := TranslateOpenAIToGemini(chatReq)
		if gErr != nil {
			return nil, fmt.Errorf("translate gemini payload: %w", gErr)
		}
		payloadBytes, err = json.Marshal(gReq)
		if err != nil {
			return nil, fmt.Errorf("marshal gemini payload: %w", err)
		}

		action := "generateContent"
		querySuffix := ""
		if chatReq.Stream {
			action = "streamGenerateContent"
			querySuffix = "alt=sse"
		}

		modelPath := targetModel
		if !strings.HasPrefix(modelPath, "models/") {
			modelPath = "models/" + modelPath
		}

		if strings.Contains(baseURL, "/v1beta") || strings.Contains(baseURL, "/v1") {
			endpointURL = fmt.Sprintf("%s/%s:%s", baseURL, modelPath, action)
		} else {
			endpointURL = fmt.Sprintf("%s/v1beta/%s:%s", baseURL, modelPath, action)
		}

		if apiKey != "" {
			if querySuffix != "" {
				querySuffix += "&key=" + url.QueryEscape(apiKey)
			} else {
				querySuffix = "key=" + url.QueryEscape(apiKey)
			}
		}
		if querySuffix != "" {
			endpointURL += "?" + querySuffix
		}

	case ProtocolAnthropic:
		// Upstream C: Anthropic Claude API (/v1/messages)
		aReq, aErr := TranslateOpenAIToAnthropic(chatReq, targetModel)
		if aErr != nil {
			return nil, fmt.Errorf("translate anthropic payload: %w", aErr)
		}
		payloadBytes, err = json.Marshal(aReq)
		if err != nil {
			return nil, fmt.Errorf("marshal anthropic payload: %w", err)
		}
		if strings.HasSuffix(baseURL, "/v1") {
			endpointURL = baseURL + "/messages"
		} else {
			endpointURL = baseURL + "/v1/messages"
		}

	case ProtocolOllama:
		// Upstream D: Local Ollama (/api/chat)
		oReq := TranslateOpenAIToOllama(chatReq, targetModel)
		payloadBytes, err = json.Marshal(oReq)
		if err != nil {
			return nil, fmt.Errorf("marshal ollama payload: %w", err)
		}
		endpointURL = baseURL + "/api/chat"

	default:
		return nil, fmt.Errorf("unsupported provider protocol: %s", prov.Protocol)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("create upstream http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if chatReq.Stream && prov.Protocol != ProtocolOllama {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("User-Agent", "NEXUS-GATE/"+GatewayVersion)

	// Protocol-Specific Auth Headers
	switch prov.Protocol {
	case ProtocolOpenAI, ProtocolOllama:
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	case ProtocolGemini:
		if apiKey != "" {
			req.Header.Set("x-goog-api-key", apiKey)
		}
	case ProtocolAnthropic:
		if apiKey != "" {
			req.Header.Set("x-api-key", apiKey)
		}
		req.Header.Set("anthropic-version", AnthropicAPIVer)
	}

	for k, v := range prov.CustomHeaders {
		req.Header.Set(k, v)
	}

	return req, nil
}

// rewriteOpenAIModelInPayload preserves all unknown/extended OpenAI fields (tools, response_format, etc.)
// while swapping the target model name for the upstream provider.
func rewriteOpenAIModelInPayload(raw []byte, targetModel string) ([]byte, error) {
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	generic["model"] = targetModel
	return json.Marshal(generic)
}

// ============================================================================
// 10. NON-STREAMING JSON RESPONSE TRANSPILER
// ============================================================================

func (g *Gateway) transpileJSONToClient(
	w http.ResponseWriter,
	upstreamBody io.Reader,
	protocol ProtocolType,
	requestedModel string,
) (int, error) {
	raw, err := io.ReadAll(upstreamBody)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "Failed reading upstream response body: "+err.Error(), "upstream_read_error", "read_failed")
		return 0, err
	}

	switch protocol {
	case ProtocolOpenAI:
		// Native pass-through (also parse completion token count if available)
		var parsed OpenAIChatResponse
		completionTok := estimateTokens(string(raw)) / 2
		if json.Unmarshal(raw, &parsed) == nil {
			if parsed.Usage != nil && parsed.Usage.CompletionTokens > 0 {
				completionTok = parsed.Usage.CompletionTokens
			} else if len(parsed.Choices) > 0 && parsed.Choices[0].Message != nil {
				completionTok = estimateTokens(parsed.Choices[0].Message.Content)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, wErr := w.Write(raw)
		return completionTok, wErr

	case ProtocolGemini:
		var gResp GeminiResponse
		if err := json.Unmarshal(raw, &gResp); err != nil {
			writeOpenAIError(w, http.StatusBadGateway, "Invalid Gemini JSON response: "+err.Error(), "transpile_error", "invalid_upstream_json")
			return 0, err
		}
		oaiResp := TranslateGeminiToOpenAI(&gResp, requestedModel)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(oaiResp)
		return oaiResp.Usage.CompletionTokens, err

	case ProtocolAnthropic:
		var aResp AnthropicResponse
		if err := json.Unmarshal(raw, &aResp); err != nil {
			writeOpenAIError(w, http.StatusBadGateway, "Invalid Anthropic JSON response: "+err.Error(), "transpile_error", "invalid_upstream_json")
			return 0, err
		}
		oaiResp := TranslateAnthropicToOpenAI(&aResp, requestedModel)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(oaiResp)
		return oaiResp.Usage.CompletionTokens, err

	case ProtocolOllama:
		var oResp OllamaChatResponse
		if err := json.Unmarshal(raw, &oResp); err != nil {
			writeOpenAIError(w, http.StatusBadGateway, "Invalid Ollama JSON response: "+err.Error(), "transpile_error", "invalid_upstream_json")
			return 0, err
		}
		oaiResp := TranslateOllamaToOpenAI(&oResp, requestedModel)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(oaiResp)
		return oaiResp.Usage.CompletionTokens, err

	default:
		writeOpenAIError(w, http.StatusInternalServerError, "Unsupported protocol", "internal_error", "unsupported_protocol")
		return 0, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// ============================================================================
// 11. REAL-TIME STREAMING ENGINE (SSE & NDJSON -> OPENAI SSE WITH FLUSHER)
// ============================================================================

func (g *Gateway) streamUpstreamToClient(
	w http.ResponseWriter,
	upstreamBody io.Reader,
	protocol ProtocolType,
	requestedModel string,
) (int, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeOpenAIError(w, http.StatusInternalServerError, "Streaming unsupported by underlying ResponseWriter", "internal_error", "flusher_unavailable")
		return 0, errors.New("http.Flusher not supported")
	}

	// Set zero-buffering SSE headers
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	streamID := "chatcmpl-" + randomHex(12)
	created := time.Now().Unix()

	switch protocol {
	case ProtocolOpenAI:
		return streamOpenAINative(w, flusher, upstreamBody)
	case ProtocolGemini:
		return streamGeminiToOpenAI(w, flusher, upstreamBody, streamID, created, requestedModel)
	case ProtocolAnthropic:
		return streamAnthropicToOpenAI(w, flusher, upstreamBody, streamID, created, requestedModel)
	case ProtocolOllama:
		return streamOllamaToOpenAI(w, flusher, upstreamBody, streamID, created, requestedModel)
	default:
		return 0, fmt.Errorf("unsupported streaming protocol: %s", protocol)
	}
}

func writeSSEChunk(w http.ResponseWriter, flusher http.Flusher, chunk *OpenAIChatResponse) error {
	data, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func writeSSEDone(w http.ResponseWriter, flusher http.Flusher) error {
	if _, err := io.WriteString(w, "data: [DONE]\n\n"); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

// Upstream A: Direct SSE pass-through with immediate chunk flushing
func streamOpenAINative(w http.ResponseWriter, flusher http.Flusher, body io.Reader) (int, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), ScannerMaxCapacity)

	var transferredChars int
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
			return estimateTokensCountFromChars(transferredChars), err
		}
		if line == "" || strings.HasPrefix(line, "data:") {
			flusher.Flush()
		}
		if strings.HasPrefix(line, "data:") && !strings.Contains(line, "[DONE]") {
			transferredChars += len(line) / 4
		}
	}
	flusher.Flush()
	return estimateTokensCountFromChars(transferredChars), scanner.Err()
}

// Upstream B: Gemini SSE (`streamGenerateContent?alt=sse`) -> OpenAI `chat.completion.chunk`
func streamGeminiToOpenAI(
	w http.ResponseWriter,
	flusher http.Flusher,
	body io.Reader,
	streamID string,
	created int64,
	requestedModel string,
) (int, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), ScannerMaxCapacity)

	sentRole := false
	totalCompletionChars := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}

		var gResp GeminiResponse
		if err := json.Unmarshal([]byte(payload), &gResp); err != nil {
			continue
		}

		if len(gResp.Candidates) == 0 {
			continue
		}
		cand := gResp.Candidates[0]

		var textDelta strings.Builder
		for _, part := range cand.Content.Parts {
			textDelta.WriteString(part.Text)
		}
		deltaStr := textDelta.String()
		totalCompletionChars += len(deltaStr)

		delta := &OpenAIDeltaMsg{
			Content: deltaStr,
		}
		if !sentRole {
			delta.Role = "assistant"
			sentRole = true
		}

		var finishReason *string
		if cand.FinishReason != "" && cand.FinishReason != "FINISH_REASON_UNSPECIFIED" {
			mapped := mapGeminiFinishReason(cand.FinishReason)
			finishReason = &mapped
		}

		chunk := &OpenAIChatResponse{
			ID:      streamID,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   requestedModel,
			Choices: []OpenAIChoice{
				{
					Index:        0,
					Delta:        delta,
					FinishReason: finishReason,
				},
			},
		}
		if err := writeSSEChunk(w, flusher, chunk); err != nil {
			return estimateTokensCountFromChars(totalCompletionChars), err
		}
	}

	_ = writeSSEDone(w, flusher)
	return estimateTokensCountFromChars(totalCompletionChars), scanner.Err()
}

// Upstream C: Anthropic SSE (`message_start`, `content_block_delta`, `message_delta`, `message_stop`) -> OpenAI `chat.completion.chunk`
func streamAnthropicToOpenAI(
	w http.ResponseWriter,
	flusher http.Flusher,
	body io.Reader,
	streamID string,
	created int64,
	requestedModel string,
) (int, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), ScannerMaxCapacity)

	sentRole := false
	sentStop := false
	totalCompletionChars := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}

		var ev AnthropicStreamEvent
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}

		switch ev.Type {
		case "message_start":
			if !sentRole {
				sentRole = true
				chunk := &OpenAIChatResponse{
					ID:      streamID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   requestedModel,
					Choices: []OpenAIChoice{
						{
							Index: 0,
							Delta: &OpenAIDeltaMsg{Role: "assistant"},
						},
					},
				}
				if err := writeSSEChunk(w, flusher, chunk); err != nil {
					return estimateTokensCountFromChars(totalCompletionChars), err
				}
			}

		case "content_block_delta":
			if ev.Delta != nil && ev.Delta.Text != "" {
				totalCompletionChars += len(ev.Delta.Text)
				delta := &OpenAIDeltaMsg{Content: ev.Delta.Text}
				if !sentRole {
					delta.Role = "assistant"
					sentRole = true
				}
				chunk := &OpenAIChatResponse{
					ID:      streamID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   requestedModel,
					Choices: []OpenAIChoice{
						{
							Index: 0,
							Delta: delta,
						},
					},
				}
				if err := writeSSEChunk(w, flusher, chunk); err != nil {
					return estimateTokensCountFromChars(totalCompletionChars), err
				}
			}

		case "message_delta":
			if ev.Delta != nil && ev.Delta.StopReason != "" {
				mapped := mapAnthropicStopReason(ev.Delta.StopReason)
				sentStop = true
				chunk := &OpenAIChatResponse{
					ID:      streamID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   requestedModel,
					Choices: []OpenAIChoice{
						{
							Index:        0,
							Delta:        &OpenAIDeltaMsg{},
							FinishReason: &mapped,
						},
					},
				}
				if err := writeSSEChunk(w, flusher, chunk); err != nil {
					return estimateTokensCountFromChars(totalCompletionChars), err
				}
			}

		case "message_stop":
			if !sentStop {
				stopStr := "stop"
				sentStop = true
				chunk := &OpenAIChatResponse{
					ID:      streamID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   requestedModel,
					Choices: []OpenAIChoice{
						{
							Index:        0,
							Delta:        &OpenAIDeltaMsg{},
							FinishReason: &stopStr,
						},
					},
				}
				_ = writeSSEChunk(w, flusher, chunk)
			}
		}
	}

	_ = writeSSEDone(w, flusher)
	return estimateTokensCountFromChars(totalCompletionChars), scanner.Err()
}

// Upstream D: Local Ollama NDJSON stream -> OpenAI `chat.completion.chunk` SSE
func streamOllamaToOpenAI(
	w http.ResponseWriter,
	flusher http.Flusher,
	body io.Reader,
	streamID string,
	created int64,
	requestedModel string,
) (int, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), ScannerMaxCapacity)

	sentRole := false
	totalCompletionChars := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var oChunk OllamaChatResponse
		if err := json.Unmarshal([]byte(line), &oChunk); err != nil {
			continue
		}

		delta := &OpenAIDeltaMsg{
			Content: oChunk.Message.Content,
		}
		if !sentRole {
			delta.Role = "assistant"
			sentRole = true
		}
		totalCompletionChars += len(oChunk.Message.Content)

		var finishReason *string
		if oChunk.Done {
			reason := "stop"
			if oChunk.DoneReason == "length" {
				reason = "length"
			}
			finishReason = &reason
		}

		chunk := &OpenAIChatResponse{
			ID:      streamID,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   requestedModel,
			Choices: []OpenAIChoice{
				{
					Index:        0,
					Delta:        delta,
					FinishReason: finishReason,
				},
			},
		}
		if err := writeSSEChunk(w, flusher, chunk); err != nil {
			return estimateTokensCountFromChars(totalCompletionChars), err
		}
	}

	_ = writeSSEDone(w, flusher)
	return estimateTokensCountFromChars(totalCompletionChars), scanner.Err()
}

// ============================================================================
// 12. UTILITIES & HELPERS
// ============================================================================

func writeOpenAIError(w http.ResponseWriter, statusCode int, message, errType, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(OpenAIErrorResponse{
		Error: OpenAIErrorDetail{
			Message: message,
			Type:    errType,
			Code:    code,
		},
	})
}

func extractClientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func estimateTokens(text string) int {
	return estimateTokensCountFromChars(len(text))
}

func estimateTokensCountFromChars(charCount int) int {
	if charCount <= 0 {
		return 0
	}
	t := (charCount + 3) / 4
	if t == 0 {
		return 1
	}
	return t
}

func estimateMessagesTokens(msgs []OpenAIMessage) int {
	total := 0
	for _, m := range msgs {
		total += 4 + estimateTokens(m.ExtractText())
	}
	return total
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-2] + ".."
}

func printStartupBanner(cfg *Config, configPath string, createdNew bool) {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", ansiBold, ansiCyan, ansiReset)
	fmt.Printf("%s%s║  NEXUS//GATE v%-6s — Minimalist Multi-Protocol AI Gateway & Failover Proxy ║%s\n", ansiBold, ansiCyan, GatewayVersion, ansiReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", ansiBold, ansiCyan, ansiReset)

	cfgState := "loaded"
	if createdNew {
		cfgState = "auto-generated default"
	}
	fmt.Printf("  %s•%s Listen Address : %shttp://%s%s\n", ansiCyan, ansiReset, ansiBold, cfg.ListenAddr, ansiReset)
	fmt.Printf("  %s•%s Configuration  : %s (%s)\n", ansiCyan, ansiReset, configPath, cfgState)
	fmt.Printf("  %s•%s Endpoints      : POST /v1/chat/completions │ GET /v1/models │ GET /health\n", ansiCyan, ansiReset)
	fmt.Printf("  %s•%s Providers (%d)  : ", ansiCyan, ansiReset, len(cfg.Providers))
	provNames := make([]string, 0, len(cfg.Providers))
	for k, p := range cfg.Providers {
		provNames = append(provNames, fmt.Sprintf("%s[%s:%d keys]", k, p.Protocol, len(p.APIKeys)))
	}
	fmt.Printf("%s\n", strings.Join(provNames, ", "))
	fmt.Printf("  %s•%s Virtual Models : %d alias chains active\n\n", ansiCyan, ansiReset, len(cfg.ModelRoutes))
}

// ============================================================================
// 13. MAIN ENTRYPOINT & GRACEFUL SHUTDOWN LIFECYCLE
// ============================================================================

func main() {
	configPath := flag.String("config", DefaultConfigPath, "Path to NEXUS//GATE config.json file")
	listenOverride := flag.String("addr", "", "Optional override for listen address (e.g. 127.0.0.1:8080)")
	selfTest := flag.Bool("selftest", false, "Run built-in multi-protocol translation & failover verification suite and exit")
	flag.Parse()

	cfg, created, err := LoadOrCreateConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[FATAL]%s Failed to initialize configuration: %v\n", ansiRed, ansiReset, err)
		os.Exit(1)
	}
	if *listenOverride != "" {
		cfg.ListenAddr = *listenOverride
	}

	if *selfTest {
		if err := runBuiltInSelfTest(); err != nil {
			fmt.Fprintf(os.Stderr, "%s[SELFTEST FAILED]%s %v\n", ansiRed, ansiReset, err)
			os.Exit(1)
		}
		fmt.Printf("%s[SELFTEST PASSED]%s All protocol transpilers, SSE flusher streams, and failover hops verified.\n", ansiGreen, ansiReset)
		return
	}

	printStartupBanner(cfg, *configPath, created)

	gateway := NewGateway(cfg)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           gateway,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	serverErrCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	select {
	case sig := <-shutdownCh:
		fmt.Printf("\n%s[NEXUS//GATE]%s Caught signal %v — initiating graceful shutdown...\n", ansiYellow, ansiReset, sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s[ERROR]%s Graceful shutdown timed out: %v\n", ansiRed, ansiReset, err)
		}
		fmt.Printf("%s[NEXUS//GATE]%s Final Telemetry: Total=%d │ Success=%d │ Failed=%d │ FailoverHops=%d │ ~Tokens=%d\n",
			ansiCyan, ansiReset,
			gateway.telemetry.totalRequests.Load(),
			gateway.telemetry.successfulRequests.Load(),
			gateway.telemetry.failedRequests.Load(),
			gateway.telemetry.failoverHopsTotal.Load(),
			gateway.telemetry.estimatedTokensTotal.Load(),
		)
	case err := <-serverErrCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[FATAL]%s HTTP server failed: %v\n", ansiRed, ansiReset, err)
			os.Exit(1)
		}
	}
}

// runBuiltInSelfTest executes an in-memory verification of protocol transpilers (Gemini, Anthropic, Ollama)
// to allow zero-dependency validation via `nexus-gate -selftest`.
func runBuiltInSelfTest() error {
	temp := 0.7
	maxTok := 512
	sampleReq := &OpenAIChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp,
		MaxTokens:   &maxTok,
		Messages: []OpenAIMessage{
			{Role: "system", Content: "You are a concise systems architect."},
			{Role: "user", Content: "Explain failover routing in one sentence."},
		},
	}

	// 1. Verify Gemini Translation
	gReq, err := TranslateOpenAIToGemini(sampleReq)
	if err != nil || gReq.SystemInstruction == nil || len(gReq.Contents) != 1 || gReq.Contents[0].Role != "user" {
		return fmt.Errorf("gemini request translation failed: %+v, err=%v", gReq, err)
	}
	gResp := &GeminiResponse{
		Candidates: []GeminiCandidate{
			{
				Content:      GeminiContent{Role: "model", Parts: []GeminiPart{{Text: "Failover routing automatically switches traffic to a backup upstream upon failure."}}},
				FinishReason: "STOP",
			},
		},
	}
	oaiFromGemini := TranslateGeminiToOpenAI(gResp, "gpt-4o")
	if len(oaiFromGemini.Choices) != 1 || oaiFromGemini.Choices[0].Message.Content == "" {
		return errors.New("gemini response translation failed")
	}

	// 2. Verify Anthropic Translation
	aReq, err := TranslateOpenAIToAnthropic(sampleReq, "claude-3-5-sonnet-20241022")
	if err != nil || aReq.System == "" || len(aReq.Messages) != 1 || aReq.Messages[0].Role != "user" {
		return fmt.Errorf("anthropic request translation failed: %+v, err=%v", aReq, err)
	}
	aResp := &AnthropicResponse{
		ID:         "msg_01XYZ",
		Role:       "assistant",
		StopReason: "end_turn",
		Content:    []AnthropicContentBlock{{Type: "text", Text: "Anthropic response verified."}},
	}
	oaiFromAnt := TranslateAnthropicToOpenAI(aResp, "claude-3-5-sonnet")
	if len(oaiFromAnt.Choices) != 1 || oaiFromAnt.Choices[0].Message.Content != "Anthropic response verified." {
		return errors.New("anthropic response translation failed")
	}

	// 3. Verify Ollama Translation
	oReq := TranslateOpenAIToOllama(sampleReq, "llama3.1:latest")
	if len(oReq.Messages) != 2 || oReq.Messages[0].Role != "system" {
		return fmt.Errorf("ollama request translation failed: %+v", oReq)
	}
	oResp := &OllamaChatResponse{
		Model:   "llama3.1:latest",
		Message: OllamaMessage{Role: "assistant", Content: "Ollama local response verified."},
		Done:    true,
	}
	oaiFromOllama := TranslateOllamaToOpenAI(oResp, "local-agent")
	if len(oaiFromOllama.Choices) != 1 || oaiFromOllama.Choices[0].Message.Content != "Ollama local response verified." {
		return errors.New("ollama response translation failed")
	}

	return nil
}