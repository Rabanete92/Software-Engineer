#pragma once
// win32_stack_env — implementación en vivo de sspoof::IStackEnv sobre Windows.
// Resuelve los hechos de cada dirección de retorno con APIs del SO para que el
// Detector (lógica pura) pueda emitir su veredicto sobre pilas reales.
//
// Primera versión: PROCESO ACTUAL (hProcess = GetCurrentProcess()). La
// clasificación usa VirtualQueryEx + GetModuleHandleExW + RtlLookupFunctionEntry
// y el call-preceded lee el código previo al retorno con ReadProcessMemory.
// [XPROC] Cross-process (otro PID) es una extensión documentada: VirtualQueryEx y
// ReadProcessMemory ya aceptan un handle remoto, pero RtlLookupFunctionEntry solo
// es válido para el proceso actual; el unwind remoto exige parsear el directorio
// de excepciones del PE en el proceso objetivo (fase posterior).
#include "stack_spoof_detector.h"
#include <windows.h>

namespace sspoof {

class Win32StackEnv : public IStackEnv {
public:
    explicit Win32StackEnv(HANDLE hProcess = GetCurrentProcess());

    FrameFacts classify(uint64_t returnAddr) const override;
    bool       isCallPreceded(uint64_t returnAddr) const override;

    // Captura la pila del hilo ACTUAL en un ThreadStack (para self-test/demo).
    static ThreadStack captureCurrent(unsigned maxFrames = 64);

private:
    bool nearThunk(uint64_t addr) const;

    HANDLE   hProcess_;
    bool     isCurrentProcess_;
    uint64_t rtlUserThreadStart_  = 0;
    uint64_t baseThreadInitThunk_ = 0;
};

} // namespace sspoof
