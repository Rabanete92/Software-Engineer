#include "win32_stack_env.h"

#pragma comment(lib, "kernel32.lib")

namespace sspoof {
namespace {
    // Ventana (en bytes) alrededor del símbolo de arranque dentro de la cual
    // consideramos que una dirección de retorno "pertenece" al thunk. El retorno
    // apunta DESPUES del call interno del thunk, de ahi el margen.
    const uint64_t kThunkWindow = 0x400;

    uint64_t procAddr(const wchar_t* mod, const char* fn) {
        HMODULE h = GetModuleHandleW(mod);
        if (!h) return 0;
        FARPROC p = GetProcAddress(h, fn);
        return reinterpret_cast<uintptr_t>(p);
    }
}

Win32StackEnv::Win32StackEnv(HANDLE hProcess)
    : hProcess_(hProcess),
      isCurrentProcess_(hProcess == GetCurrentProcess()) {
    // Las DLLs del sistema comparten base en la sesion, asi que estas direcciones
    // locales sirven tambien como referencia para un proceso objetivo [XPROC].
    rtlUserThreadStart_  = procAddr(L"ntdll.dll",    "RtlUserThreadStart");
    baseThreadInitThunk_ = procAddr(L"kernel32.dll", "BaseThreadInitThunk");
}

bool Win32StackEnv::nearThunk(uint64_t addr) const {
    const uint64_t a = rtlUserThreadStart_, b = baseThreadInitThunk_;
    if (a && addr >= a && addr < a + kThunkWindow) return true;
    if (b && addr >= b && addr < b + kThunkWindow) return true;
    return false;
}

FrameFacts Win32StackEnv::classify(uint64_t returnAddr) const {
    FrameFacts f;

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(hProcess_,
                       reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(returnAddr)),
                       &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const bool  commit = (mbi.State == MEM_COMMIT);
        const DWORD prot   = mbi.Protect & 0xFFu;
        const DWORD execBits = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        f.executable  = commit && ((prot & execBits) != 0);
        f.imageBacked = (mbi.Type == MEM_IMAGE);   // respaldado por archivo en disco
    }

    HMODULE hm = nullptr;
    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(static_cast<uintptr_t>(returnAddr)), &hm) && hm) {
        f.inModule = true;
    }

    // [XPROC] RtlLookupFunctionEntry solo es valido para el proceso actual.
    if (isCurrentProcess_) {
        DWORD64 imageBase = 0;
        if (RtlLookupFunctionEntry(static_cast<DWORD64>(returnAddr), &imageBase, nullptr) != nullptr)
            f.hasUnwindInfo = true;
    }

    f.isThreadStartThunk = nearThunk(returnAddr);
    return f;
}

bool Win32StackEnv::isCallPreceded(uint64_t returnAddr) const {
    // Lee los 16 bytes previos al retorno y busca una codificacion de `call` que
    // termine exactamente en returnAddr. Heuristica estandar (no exhaustiva): un
    // retorno legitimo siempre lo dejo en la pila el `call` inmediatamente
    // anterior; un frame forjado "a mano" no tiene ese call delante.
    unsigned char buf[16];
    if (returnAddr < sizeof(buf)) return false;
    const uint64_t start = returnAddr - sizeof(buf);

    SIZE_T got = 0;
    if (!ReadProcessMemory(hProcess_,
                           reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(start)),
                           buf, sizeof(buf), &got) || got != sizeof(buf))
        return false;   // ilegible -> no podemos confirmar call-preceded

    // buf[15] = byte en returnAddr-1.
    // (a) call rel32: E8 cc cc cc cc  (opcode en returnAddr-5 = buf[11]).
    if (buf[11] == 0xE8) return true;

    // (b) call r/m (FF /2) o call m16:xx (FF /3): un FF en returnAddr-7..-2 con
    //     ModRM.reg == 2 o 3. La instruccion mide 2..7 bytes.
    for (int k = 2; k <= 7; ++k) {
        const unsigned char op = buf[16 - k];
        if (op == 0xFF) {
            const unsigned char modrm = buf[16 - k + 1];
            const unsigned char reg   = static_cast<unsigned char>((modrm >> 3) & 7u);
            if (reg == 2u || reg == 3u) return true;
        }
    }

    // (c) call far absoluto 9A (legacy): opcode en returnAddr-7 = buf[9].
    if (buf[9] == 0x9A) return true;

    return false;
}

ThreadStack Win32StackEnv::captureCurrent(unsigned maxFrames) {
    ThreadStack s;

    const unsigned cap = (maxFrames < 62u) ? maxFrames : 62u;   // margen de RtlCapture
    void* frames[62] = {};
    const USHORT n = RtlCaptureStackBackTrace(0, static_cast<ULONG>(cap), frames, nullptr);
    for (USHORT i = 0; i < n; ++i)
        s.frames.push_back(static_cast<uint64_t>(reinterpret_cast<uintptr_t>(frames[i])));

    // Limites de pila del hilo actual, desde el TIB/TEB.
    const NT_TIB* tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
    s.stackBase  = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(tib->StackBase));
    s.stackLimit = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(tib->StackLimit));

    // RSP aproximado: una variable local vive en la pila del hilo actual.
    volatile int probe = 0;
    s.rsp = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&probe));
    (void)probe;
    return s;
}

} // namespace sspoof
