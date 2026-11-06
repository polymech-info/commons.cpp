#include "core/command_finish_i18n.hpp"

#include "core/settings_store.hpp"

#include <string>
#include "string/string_utils.hpp"

namespace media::command_finish_i18n {
namespace {


static const Strings kEn{
    "Command finished",
    " finished",
    "Command failed",
    " failed",
    "Command",
    "exit ",
    " more",
    L" more",
};

static const Strings kEs{
    "Comando terminado",
    " terminado",
    "Comando fallido",
    " fallido",
    "Comando",
    "salida ",
    " más",
    L" más",
};

static const Strings kDe{
    "Befehl abgeschlossen",
    " abgeschlossen",
    "Befehl fehlgeschlagen",
    " fehlgeschlagen",
    "Befehl",
    "Exit ",
    " weitere",
    L" weitere",
};

static const Strings kIt{
    "Comando completato",
    " completato",
    "Comando non riuscito",
    " non riuscito",
    "Comando",
    "uscita ",
    " altri",
    L" altri",
};

static const Strings kFr{
    "Commande terminée",
    " terminée",
    "Commande échouée",
    " échouée",
    "Commande",
    "sortie ",
    " de plus",
    L" de plus",
};

const Strings& load_current()
{
    nlohmann::json appearance;
    std::string err;
    if (media::settings::load_subtree("appearance", appearance, err) && appearance.is_object()
        && appearance.contains("display_language") && appearance["display_language"].is_string()) {
        const std::string lang = appearance["display_language"].get<std::string>();
        if (!lang.empty())
            return strings_for(lang);
    }
    return kEn;
}

} // namespace

const Strings& strings_for(std::string_view display_language)
{
    const std::string c = media::strutil::lower_ascii(std::string(display_language));
    if (c == "es")
        return kEs;
    if (c == "de")
        return kDe;
    if (c == "it")
        return kIt;
    if (c == "fr")
        return kFr;
    return kEn;
}

const Strings& current()
{
    static const Strings& cached = load_current();
    return cached;
}

} // namespace media::command_finish_i18n
