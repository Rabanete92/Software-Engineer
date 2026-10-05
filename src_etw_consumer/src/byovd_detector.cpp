#include "byovd_detector.h"

#include <fstream>
#include <sstream>

namespace byovd {
namespace {

std::string lowerAscii(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (char c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        o.push_back(c);
    }
    return o;
}

// Nombre de archivo (minúsculas, ASCII) a partir de una ruta wide.
std::string baseNameLowerAscii(const std::wstring& path) {
    const size_t cut = path.find_last_of(L"\\/");
    const std::wstring fn = (cut == std::wstring::npos) ? path : path.substr(cut + 1);
    std::string o; o.reserve(fn.size());
    for (wchar_t wc : fn) {
        char c = (wc < 128) ? static_cast<char>(wc) : '?';
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        o.push_back(c);
    }
    return o;
}

std::wstring widen(const std::string& s) {
    std::wstring o; o.reserve(s.size());
    for (char c : s) o.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    return o;
}

std::wstring toLowerW(const std::wstring& s) {
    std::wstring o; o.reserve(s.size());
    for (wchar_t c : s) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        o.push_back(c);
    }
    return o;
}

Severity maxSev(Severity a, Severity b) {
    return (static_cast<int>(a) >= static_cast<int>(b)) ? a : b;
}

} // namespace

const wchar_t* severityName(Severity s) {
    switch (s) {
        case Severity::High:   return L"HIGH";
        case Severity::Medium: return L"MEDIUM";
        case Severity::Low:    return L"LOW";
        case Severity::Info:   return L"INFO";
    }
    return L"INFO";
}

Detector::Detector() {
    // Semilla compilada: nombres de libro público (LOLDrivers / blocklist MS).
    // Sin hashes inventados: el match por nombre vale; el hash se rellena en el
    // CSV cuando se dispone de uno verificado.
    entries_ = {
        { "capcom.sys",     "", "Capcom.sys: ejecucion/mapeo en kernel via IOCTL (clasico BYOVD)" },
        { "gdrv.sys",       "", "Gigabyte gdrv.sys: R/W de memoria fisica via IOCTL sin control de acceso" },
        { "rtcore64.sys",   "", "MSI RTCore64: R/W de memoria y MSR via IOCTL" },
        { "dbutil_2_3.sys", "", "Dell dbutil_2_3: R/W de memoria fisica via IOCTL" },
    };
}

size_t Detector::loadCatalog(const std::wstring& csvPath) {
    std::ifstream f(csvPath.c_str());   // ctor wide: extensión MSVC
    if (!f) return 0;
    size_t added = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const size_t p = line.find_first_not_of(" \t");
        if (p == std::string::npos || line[p] == '#') continue;   // vacía / comentario

        std::string cols[3];
        std::stringstream ss(line);
        for (int i = 0; i < 3 && std::getline(ss, cols[i], ','); ++i) { /* split */ }
        if (cols[0].empty()) continue;

        VulnEntry e;
        e.name   = lowerAscii(cols[0]);
        e.sha256 = lowerAscii(cols[1]);
        e.reason = cols[2];
        entries_.push_back(e);
        ++added;
    }
    return added;
}

Verdict Detector::evaluate(const ImageLoad& img) const {
    Verdict v;
    const std::string fname = baseNameLowerAscii(img.path);
    const std::string hash  = lowerAscii(img.sha256);

    for (const VulnEntry& e : entries_) {
        const bool hashHit = (!e.sha256.empty() && !hash.empty() && e.sha256 == hash);
        const bool nameHit = (!e.name.empty() && e.name == fname);
        if (hashHit) {
            v.severity = maxSev(v.severity, Severity::High);
            v.reasons.push_back(L"hash en lista de drivers vulnerables: " + widen(e.reason));
        } else if (nameHit) {
            v.severity = maxSev(v.severity, Severity::High);
            v.reasons.push_back(L"nombre en lista de drivers vulnerables: " + widen(e.reason));
        }
    }

    // Heurística de ruta: driver cargado desde ubicación escribible por usuario.
    if (img.kernelMode) {
        const std::wstring lp = toLowerW(img.path);
        const wchar_t* userWritable[] = {
            L"\\users\\", L"\\temp\\", L"\\appdata\\",
            L"\\downloads\\", L"\\programdata\\", L"\\windows\\temp\\"
        };
        for (const wchar_t* frag : userWritable) {
            if (lp.find(frag) != std::wstring::npos) {
                v.severity = maxSev(v.severity, Severity::Medium);
                v.reasons.push_back(std::wstring(L"driver desde ruta escribible por usuario: ") + frag);
                break;
            }
        }
    }

    if (v.reasons.empty()) v.reasons.push_back(L"sin indicadores");
    return v;
}

} // namespace byovd
