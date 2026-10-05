#include "etw_consumer.h"
#include "correlation.h"
#include "byovd_detector.h"
#include "image_load_consumer.h"

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

// PoC: sin bucle SCM completo (handler de servicio omitido por brevedad).
// Modos:
//   edrsvc run                       -> arranca el consumidor ETW (foreground)
//   edrsvc install                   -> instala el servicio y lo marca PPL-AM
//   edrsvc byovd <csv|-> <ruta> [kernel] -> audita una carga de driver (BYOVD)
//   edrsvc imgwatch [csv]            -> watch de image-load en vivo -> BYOVD
//   edrsvc enumprops <bus> <d> <f>   -> vuelca claves de propiedad del devnode

static EtwConsumer*       g_consumer = nullptr;
static ImageLoadConsumer* g_img      = nullptr;

static BOOL WINAPI ctrlHandler(DWORD) {
    if (g_consumer) g_consumer->stop();
    if (g_img)      g_img->stop();
    return TRUE;
}

static int doRun() {
    EtwConsumer consumer([](const FaultEvent& ev) { correlation::correlate(ev); });
    g_consumer = &consumer;
    SetConsoleCtrlHandler(ctrlHandler, TRUE);
    if (!consumer.start()) { fwprintf(stderr, L"start() fallo (admin? provider?)\n"); return 1; }
    wprintf(L"Consumidor DMA-EDR activo. Ctrl+C para salir.\n");
    consumer.run();
    return 0;
}

static int doInstall() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { fwprintf(stderr, L"OpenSCManager fallo %lu\n", GetLastError()); return 1; }

    wchar_t path[MAX_PATH]; GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t cmd[MAX_PATH + 8]; swprintf(cmd, _countof(cmd), L"\"%s\" run", path);

    SC_HANDLE svc = CreateServiceW(scm, L"EdrDmaWatch", L"DMA-EDR PoC",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, cmd, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) svc = OpenServiceW(scm, L"EdrDmaWatch", SERVICE_ALL_ACCESS);
    if (!svc) { fwprintf(stderr, L"CreateService fallo %lu\n", GetLastError());
                CloseServiceHandle(scm); return 1; }

    // (3) Pieza runtime de PPL: marcar el lanzamiento como anti-malware light.
    //     SÓLO surte efecto si el binario va firmado con el cert AM y lleva
    //     /INTEGRITYCHECK (ver CMakeLists.txt y README). Sin eso, el arranque
    //     del servicio protegido fallará.
    SERVICE_LAUNCH_PROTECTED_INFO lp{};
    lp.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
    if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_LAUNCH_PROTECTED, &lp))
        fwprintf(stderr, L"[aviso] no se pudo marcar PPL-AM: %lu\n", GetLastError());

    wprintf(L"Servicio instalado. (Recuerda: PPL exige firma AM + /INTEGRITYCHECK)\n");
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return 0;
}

static int doByovd(int argc, wchar_t** argv) {
    // edrsvc byovd <catalogo.csv|-> <ruta_driver> [kernel]
    byovd::Detector det;
    if (_wcsicmp(argv[2], L"-") != 0) {
        const size_t n = det.loadCatalog(argv[2]);
        wprintf(L"catalogo: +%zu entradas (total %zu)\n", n, det.size());
    }
    byovd::ImageLoad img;
    img.path       = argv[3];
    img.kernelMode = (argc >= 5 && _wcsicmp(argv[4], L"kernel") == 0);

    const byovd::Verdict v = det.evaluate(img);
    wprintf(L"[BYOVD] %s  sev=%s\n", img.path.c_str(), byovd::severityName(v.severity));
    for (const std::wstring& r : v.reasons) wprintf(L"   - %s\n", r.c_str());
    return v.alert() ? 2 : 0;
}

static int doImgwatch(int argc, wchar_t** argv) {
    byovd::Detector det;
    if (argc >= 3 && _wcsicmp(argv[2], L"-") != 0) {
        const size_t n = det.loadCatalog(argv[2]);
        wprintf(L"catalogo: +%zu entradas (total %zu)\n", n, det.size());
    }
    ImageLoadConsumer consumer(&det);
    g_img = &consumer;
    SetConsoleCtrlHandler(ctrlHandler, TRUE);
    if (!consumer.start()) {
        fwprintf(stderr, L"imgwatch start() fallo (admin? provider?)\n");
        return 1;
    }
    wprintf(L"Image-load watch activo (stack trace ON). Ctrl+C para salir.\n");
    consumer.run();
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && _wcsicmp(argv[1], L"run") == 0)      return doRun();
    if (argc >= 2 && _wcsicmp(argv[1], L"install") == 0)  return doInstall();
    if (argc >= 2 && _wcsicmp(argv[1], L"imgwatch") == 0) return doImgwatch(argc, argv);
    if (argc >= 4 && _wcsicmp(argv[1], L"byovd") == 0)    return doByovd(argc, argv);
    if (argc >= 5 && _wcsicmp(argv[1], L"enumprops") == 0) {
        correlation::enumerateProperties(
            (uint8_t)wcstoul(argv[2], nullptr, 16),
            (uint8_t)wcstoul(argv[3], nullptr, 16),
            (uint8_t)wcstoul(argv[4], nullptr, 16));
        return 0;
    }
    wprintf(L"Uso: edrsvc [run | install | imgwatch [csv] | "
            L"byovd <csv|-> <ruta> [kernel] | enumprops <bus> <dev> <func>]\n");
    return 0;
}
