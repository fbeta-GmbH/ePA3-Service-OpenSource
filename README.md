# ePA 3.x Integration

Dieses Repository enthält die gemeinsam genutzten Komponenten für die ePA-3.x-Integration:

- VAU-Kanal und verschlüsselter Nachrichtentransport
- Kommunikation mit dem Konnektor
- Authentifizierung über den zentralen IDP
- TI-Truststore und Zertifikatsprüfung
- gemeinsame SOAP-/XML-Verarbeitung
- Erzeugung der Requests für den Dokumenten-Upload

Das Repository behält den Namen `ePA3-Service-OpenSource`. Das installierbare Python-Paket heißt `epa-core` und wird über `epa_core` importiert.


## Voraussetzungen

- Python 3.12 oder höher
- TI-Terminal-CA-Konnektor
- Konnektor-Zertifikat als `.p12`-Datei
- Zugriff auf die verwendete TI-Umgebung

Für `liboqs` werden auf Linux zusätzlich CMake, ein C-Compiler und die OpenSSL-Header benötigt.

## Installation

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Unter Windows kann weiterhin `install_dependencies.ps1` verwendet werden:

```powershell
./install_dependencies.ps1
```

## Umgebungskonfiguration

1. Kopieren Sie die Datei `config/.env.template` nach `config/.env`:

   ```bash
   cp config/.env.template config/.env
   ```

2. Legen Sie das Konnektor-Zertifikat als `.p12`-Datei im Verzeichnis `config/` ab.

3. Tragen Sie die Werte für Umgebung, Konnektor, SMC-B-Kontext und Provider in `config/.env` ein.

Die Konfiguration wird von der aufrufenden Anwendung geladen:

```python
from epa_core import bootstrap_environment

bootstrap_environment("/path/to/config")
```

Anschließend können die Core-Komponenten importiert werden, zum Beispiel:

```python
from epa_core.konnektor.Konnektor import Konnektor
from epa_core.vau.VAUProtokoll import VAUKanal
```

Der Standalone-Client kann nach der Konfiguration direkt aus dem Repository gestartet werden:

```bash
python examples/client.py
```

## Paket bauen

```bash
python -m pip install build
python -m build
```

## Tests

Der Boundary-Test prüft, dass der Core keine Abhängigkeit auf API, Full, FastAPI oder Redis enthält und dass Search und Retrieve nicht im VAU-Core implementiert sind:

```bash
python -m pytest -q tests/test_package_boundary.py
```

## Fehlerbehandlung

Bei Problemen überprüfen Sie bitte:

- Liegt die `.p12`-Datei im Konfigurationsverzeichnis?
- Ist die `.env`-Datei vollständig befüllt?
- Ist das TI-VPN beziehungsweise Split-DNS aktiv?
- Ist der Konnektor erreichbar?
- Ist der SMC-B-PIN verifiziert?

# License from fbeta GmbH

This work is provided by fbeta GmbH and licensed under the Creative Commons Attribution-NoDerivatives 4.0 International License.

For more information about the license, visit:
https://creativecommons.org/licenses/by-nd/4.0/

© fbeta GmbH. All rights reserved.

# Kontakt

Bei Fragen melden Sie sich gerne per Mail an epa@fbeta.de.
