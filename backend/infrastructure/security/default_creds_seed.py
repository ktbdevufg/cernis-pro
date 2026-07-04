"""Mitgelieferte Standardzugangs-Liste (Seed) -- reine Datenkonstante (Etappe A).

``SEED_EINTRAEGE`` ist das kuratierte Werks-Credential-Wissen als DATEN. Jeder Eintrag
traegt ``herkunft="mitgeliefert"`` (steuert ``reset_auf_standard`` -- nur diese Zeilen
werden zurueckgesetzt) und ``aktiv=True``. Die ``eintrag_id`` ist sprechend, eindeutig
und kleingeschrieben (z. B. "seed-netgear-legacy"), damit sie stabil referenzierbar ist.

KEINE UMLAUTE in Strings (ae/oe/ue/ss ausgeschrieben, Projektkonvention). Der Adapter
(``default_creds_list_db.SqliteDefaultCredsListRepository.ensure_seeded``) fuellt diese
Konstante beim Erst-Start ein -- die Verdrahtung im Composition Root ist NICHT Teil
dieser Etappe.

DREI ARTEN VON EINTRAEGEN:

* ``zustand="hat_defaults"`` -- Geraete mit bekannten Werks-Credentials (mindestens ein
  Kandidat mit Konfidenz). Aeltere Consumer-Router ab Werk mit admin/admin & Co.
* ``zustand="keine_bekannten_defaults"`` -- Geraete, die POSITIV secure-by-default sind
  (kein Kandidat): FritzBox, Eero, Nest, moderne Mesh-/ISP-Router. Fuer die zwei
  generischen Faelle (Xiaomi/Honor, moderne ISP-Router) waere die Belegung nur
  "auch_moeglich"; da es hier aber keine Kandidaten gibt, kann die Konfidenz nicht am
  Kandidaten haengen -- das ist ok, der Eintrag hat schlicht keine Kandidaten.
* ``modell=""`` -- herstellerweiter Fallback bzw. generischer Eintrag (Matching im
  Adapter behandelt leeres Modell als Hersteller-Fallback).

``quelle_url`` verweist je Hersteller auf die offizielle Support-/FAQ-Seite (wo bekannt),
sonst auf eine stabile Nachschlage-Seite.
"""

from domain.security import CredentialKandidat, DefaultCredsEintrag

__all__ = ["SEED_EINTRAEGE"]


SEED_EINTRAEGE: tuple[DefaultCredsEintrag, ...] = (
    # ── hat_defaults: aeltere Geraete mit bekannten Werks-Credentials ────────
    DefaultCredsEintrag(
        eintrag_id="seed-netgear-legacy",
        hersteller="Netgear",
        modell="aeltere Consumer",
        zustand="hat_defaults",
        kandidaten=(
            CredentialKandidat(username="admin", password="password", konfidenz="gesichert"),
            CredentialKandidat(username="admin", password="1234", konfidenz="auch_moeglich"),
        ),
        quelle_url="https://kb.netgear.com/1148/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-tplink-legacy",
        hersteller="TP-Link",
        modell="aeltere (Archer C7, TL-WR841N)",
        zustand="hat_defaults",
        kandidaten=(CredentialKandidat(username="admin", password="admin", konfidenz="gesichert"),),
        quelle_url="https://www.tp-link.com/support/faq/87/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-asus-legacy",
        hersteller="Asus",
        modell="aeltere (Blue-GUI, RT-Reihe)",
        zustand="hat_defaults",
        kandidaten=(CredentialKandidat(username="admin", password="admin", konfidenz="gesichert"),),
        quelle_url="https://www.asus.com/support/faq/1005263/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-dlink-legacy",
        hersteller="D-Link",
        modell="Mehrheit aeltere",
        zustand="hat_defaults",
        kandidaten=(
            CredentialKandidat(username="admin", password="", konfidenz="gesichert"),
            CredentialKandidat(username="admin", password="admin", konfidenz="auch_moeglich"),
        ),
        quelle_url="https://www.dlink.com/us/en/support",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-linksys-legacy",
        hersteller="Linksys",
        modell="klassisch",
        zustand="hat_defaults",
        kandidaten=(
            CredentialKandidat(username="admin", password="admin", konfidenz="gesichert"),
            CredentialKandidat(username="", password="admin", konfidenz="auch_moeglich"),
        ),
        quelle_url="https://www.linksys.com/support",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-zyxel-legacy",
        hersteller="Zyxel",
        modell="Mehrheit",
        zustand="hat_defaults",
        kandidaten=(CredentialKandidat(username="admin", password="1234", konfidenz="gesichert"),),
        quelle_url="https://www.zyxel.com/support",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-huawei-legacy",
        hersteller="Huawei",
        modell="aeltere Modelle",
        zustand="hat_defaults",
        kandidaten=(CredentialKandidat(username="admin", password="admin", konfidenz="gesichert"),),
        quelle_url="https://consumer.huawei.com/en/support/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-tenda-2018-2023",
        hersteller="Tenda",
        modell="2018-2023",
        zustand="hat_defaults",
        kandidaten=(
            CredentialKandidat(username="admin", password="admin", konfidenz="gesichert"),
            CredentialKandidat(username="admin", password="password", konfidenz="auch_moeglich"),
            CredentialKandidat(username="admin", password="1234", konfidenz="vermutet"),
        ),
        quelle_url="https://www.tendacn.com/faq/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-ubiquiti-legacy",
        hersteller="Ubiquiti",
        modell="UniFi/EdgeOS aeltere",
        zustand="hat_defaults",
        kandidaten=(CredentialKandidat(username="ubnt", password="ubnt", konfidenz="gesichert"),),
        quelle_url="https://help.ui.com/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-generisch-budget",
        hersteller="generisch (Budget)",
        modell="",
        zustand="hat_defaults",
        kandidaten=(
            CredentialKandidat(username="admin", password="admin", konfidenz="vermutet"),
            CredentialKandidat(username="admin", password="1234", konfidenz="vermutet"),
        ),
        quelle_url="https://www.routerpasswords.com/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    # ── keine_bekannten_defaults: secure-by-default (keine Kandidaten) ───────
    DefaultCredsEintrag(
        eintrag_id="seed-avm-fritzbox",
        hersteller="AVM",
        modell="FritzBox (alle)",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://avm.de/service/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-eero-alle",
        hersteller="Eero",
        modell="alle",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://support.eero.com/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-google-nest-wifi",
        hersteller="Google Nest WiFi",
        modell="alle",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://support.google.com/googlenest/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-tplink-deco",
        hersteller="TP-Link",
        modell="Deco-Serie",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://www.tp-link.com/support/faq/87/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-tplink-archer-modern",
        hersteller="TP-Link",
        modell="Archer Wi-Fi 5/6/7 ab ca. 2019",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://www.tp-link.com/support/faq/87/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-netgear-modern",
        hersteller="Netgear",
        modell="neuere (Nighthawk/Orbi)",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://kb.netgear.com/1148/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-asus-modern",
        hersteller="Asus",
        modell="neuere / ExpertWiFi",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://www.asus.com/support/faq/1005263/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-dlink-modern",
        hersteller="D-Link",
        modell="nach 2017 (secure by default)",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://www.dlink.com/us/en/support",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-xiaomi-honor-huawei-modern",
        hersteller="Xiaomi/Honor/neuere Huawei",
        modell="",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://www.mi.com/global/support/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
    DefaultCredsEintrag(
        eintrag_id="seed-moderne-isp-router",
        hersteller="moderne ISP-Router",
        modell="",
        zustand="keine_bekannten_defaults",
        kandidaten=(),
        quelle_url="https://www.routerpasswords.com/",
        aktiv=True,
        herkunft="mitgeliefert",
    ),
)
