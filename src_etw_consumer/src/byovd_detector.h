#pragma once
// byovd_detector — auditoría DEFENSIVA de carga de drivers (BYOVD).
// Dada una carga de imagen {ruta, base, modo kernel, hash?, firmante?}, puntúa
// contra un catálogo de drivers vulnerables conocidos (semilla compilada +
// CSV editable) y una heurística de ruta, y emite un veredicto accionable.
// No ejecuta ni carga nada: solo clasifica telemetría.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace byovd {

struct VulnEntry {
    std::string name;    // nombre de archivo en minúsculas (p.ej. "capcom.sys")
    std::string sha256;  // hash hex en minúsculas, "" si no se conoce
    std::string reason;  // por qué está en la lista
};

struct ImageLoad {
    std::wstring path;              // ruta completa de la imagen cargada
    uint64_t     imageBase = 0;
    bool         kernelMode = false;// ¿driver (carga en kernel)?
    std::string  sha256;            // hash si la telemetría lo aporta ("")
    std::string  signer;            // firmante si se conoce ("")
};

enum class Severity { Info = 0, Low = 1, Medium = 2, High = 3 };
const wchar_t* severityName(Severity s);

struct Verdict {
    Severity severity = Severity::Info;
    std::vector<std::wstring> reasons;
    bool alert() const {
        return static_cast<int>(severity) >= static_cast<int>(Severity::Medium);
    }
};

class Detector {
public:
    Detector();   // carga la semilla compilada

    // Carga un catálogo CSV ("name,sha256,reason" por línea; # = comentario;
    // sha256 opcional). Devuelve nº de entradas añadidas; si no abre, mantiene
    // la semilla y devuelve 0.
    size_t loadCatalog(const std::wstring& csvPath);

    Verdict evaluate(const ImageLoad& img) const;
    size_t  size() const { return entries_.size(); }

private:
    std::vector<VulnEntry> entries_;
};

} // namespace byovd
