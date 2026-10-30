# ePA 3.x Integration

Dieses Projekt stellt Python-Komponenten für die Integration der elektronischen Patientenakte (ePA) 3.x bereit.

Es implementiert unter anderem:
- den AuthZ-Workflow für den Zugriff auf die elektronische Patientenakte
- die Kommunikation mit dem TI-Konnektor
- die Authentifizierung über den zentralen IDP
- den verschlüsselten Nachrichtenaustausch über den VAU-Kanal
- die Zertifikatsprüfung über den TI-Truststore
- die Erstellung von Requests zum Hochladen medizinischer Dokumente (z. B. MIOs)

## Voraussetzungen

- Python 3.12 oder höher
- TI-Konnektor mit entsprechendem Zugriff auf die TI-Umgebung
- Konnektor-Zertifikat als `.p12`-Datei

Unter Linux werden für die Installation von `liboqs` zusätzlich CMake, ein C-Compiler und die OpenSSL-Header benötigt.

## Installation

Installieren Sie die benötigten Python-Abhängigkeiten:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Unter Windows kann alternativ das PowerShell-Skript verwendet werden:

```powershell
./install_dependencies.ps1
```

## Umgebungskonfiguration

1. Kopieren Sie die Datei `config/.env.template` nach `config/.env`:

   ```bash
   cp config/.env.template config/.env
   ```

2. Legen Sie das Konnektor-Zertifikat als `.p12`-Datei im Verzeichnis `config/` ab.

3. Tragen Sie die benötigten Umgebungsvariablen in `config/.env` ein.

### Basis-Konfiguration

- `EPA_ENVIRONMENT`: ePA-Umgebung (z. B. `RU`, `RT`, `PROD`)
- `DEFAULT_EPA_PROVIDER_ID`: ID des ePA-Aktenkontoanbieters
- `USER_AGENT`: User-Agent für HTTP-Anfragen
- `KONNEKTOR_URL`: URL des TI-Konnektors
- `KONNEKTOR_CERT_PW`: Passwort des Konnektor-Zertifikats
- `KONNEKTOR_TLS_MODE`: Modus für die TLS-Verbindung zum Konnektor
  - `smc_k`: Zertifikatsprüfung über den TI-Truststore (empfohlen)
  - `alternative`: Verwendung eines alternativen Konnektor-Zertifikats
  - `insecure`: Deaktivierte Zertifikatsprüfung (nicht für den Produktivbetrieb geeignet)
- `HTTPS_TIMEOUT`: Timeout für HTTPS-Anfragen in Sekunden (Standard: `30`)
- `RECORD_PROVIDER_1`: Name des ersten ePA-Providers
- `RECORD_PROVIDER_2`: Name des zweiten ePA-Providers

### DiGA-Identifikation

Die folgenden Variablen werden zur Erstellung des Author-Strings verwendet:

- `DIGA_NAME`: Name der DiGA
- `DIGA_MANUFACTURER`: Name des DiGA-Herstellers
- `SW_ADDITION_1`: Ergänzung der Softwarebezeichnung (optional)
- `SW_ADDITION_2`: Ergänzung der Softwarebezeichnung (optional)
- `SW_ADDITION_3`: Ergänzung der Softwarebezeichnung (optional)
- `AUTHOR`: Vollständiger Author-String (optional, überschreibt die einzelnen Angaben)

### Konnektor-Workspace

- `MANDANT_ID`: ID des Mandanten im Konnektor
- `CLIENT_SYSTEM_ID`: ID des Client-Systems im Konnektor
- `WORKPLACE_ID`: ID des Arbeitsplatzes im Konnektor
- `USER_ID`: ID des Benutzers (optional)

### Logging

- `LOG_LEVEL`: Logging-Level (z. B. `INFO`, `DEBUG`, `ERROR`)

## Verwendung

### Standalone-Client

Der Beispielclient kann direkt aus dem Repository gestartet werden:

```bash
python examples/client.py
```

Die erforderlichen Einstellungen werden aus `config/.env` geladen. Für den Zugriff auf eine Patientenakte müssen eine gültige Versicherten-ID und die entsprechenden Metadaten hinterlegt sein.

### Verwendung als Python-Paket

Die Komponenten können auch in anderen Python-Anwendungen verwendet werden.

Initialisieren Sie dazu zunächst die Umgebungskonfiguration:

```python
from epa_core import bootstrap_environment

bootstrap_environment("/path/to/config")
```

Anschließend können die benötigten Komponenten importiert werden:

```python
from epa_core.konnektor.Konnektor import Konnektor
from epa_core.vau.VAUProtokoll import VAUKanal
```

## Paket bauen

Zur Erstellung eines installierbaren Python-Pakets:

```bash
python -m pip install build
python -m build
```

## Fehlerbehandlung

Bei Problemen überprüfen Sie bitte:

- Ist die `.p12`-Datei im Konfigurationsverzeichnis vorhanden?
- Ist `config/.env` vollständig und korrekt befüllt?
- Ist die TI-Umgebung über VPN bzw. Split-DNS erreichbar?
- Ist der TI-Konnektor erreichbar?
- Ist die SMC-B-PIN verifiziert?
- Sind die Versicherten-ID und die Metadaten korrekt?

## Lizenz

This work is provided by fbeta GmbH and licensed under the Creative Commons Attribution-NoDerivatives 4.0 International License.

For more information about the license, visit:
https://creativecommons.org/licenses/by-nd/4.0/

© fbeta GmbH. All rights reserved.

## Kontakt

Bei Fragen wenden Sie sich gerne per Mail an epa@fbeta.de.
