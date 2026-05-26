# ePA 3.x Integration

Dieses Projekt implementiert:
- den AuthZ-Workflow für die elektronische Patientenakte (ePA) 3.x.
- das Schreiben eines Medizinischen Informationsobjekt (MIO) in die elektronische Patientenakte.

## Voraussetzungen

- Python 3.12 oder höher
- PowerShell
- TI-Terminal-CA (Konnektor) Zertifikat als `.p12`-Datei

## Installation

Um alle notwendigen Abhängigkeiten zu installieren, führen Sie das Skript `install_dependencies.ps1` aus:

```powershell
./install_dependencies.ps1
```

## Umgebungskonfiguration

1. Kopieren Sie die Datei `config/.env.template` zu `config/.env`:
   ```bash
   cp config/.env.template config/.env
   ```

2. Füllen Sie die folgenden Umgebungsvariablen in der Datei `config/.env` aus:

### Basis-Konfiguration
- `EPA_ENVIRONMENT`: Umgebung der ePA (z. B. `RU`, `RT`, `PROD`)
- `DEFAULT_EPA_PROVIDER_ID`: ID des ePA-Aktenkontoanbieters (z. B. `1` für IBM, `2` für Bitmarck Technik / RISE)
- `USER_AGENT`: User Agent String für HTTP-Requests
- `KONNEKTOR_URL`: URL des Konnektors

### DiGA-Identifikation
Folgende Variablen werden zur Erstellung des Author-Strings verwendet:
- `DIGA_NAME`: Name Ihrer DiGA (Name der Verordnungseinheit)
- `DIGA_MANUFACTURER`: Name des DiGA-Herstellers
- `SW_ADDITION_1`: Ergänzung der Bezeichnung der SW 1 (optional)
- `SW_ADDITION_2`: Ergänzung der Bezeichnung der SW 2 (optional)
- `SW_ADDITION_3`: Ergänzung der Bezeichnung der SW 3 (optional)

Alternativ können Sie auch direkt den kompletten Author-String setzen:
- `AUTHOR`: Vollständiger Author-String (optional, überschreibt die einzelnen DiGA-Variablen)

### Konnektor-Workspace
- `MANDANT_ID`: ID des eingerichteten Mandanten im Konnektor
- `CLIENT_SYSTEM_ID`: ID des eingerichteten Client-Systems im Konnektor
- `WORKPLACE_ID`: ID des eingerichteten Arbeitsplatzes im Konnektor

### Logging
- `LOG_LEVEL`: Logging-Level (INFO, DEBUG, ERROR, etc.)

## Konfiguration

1. Legen Sie das Konnektor-Zertifikat als `.p12`-Datei im Verzeichnis `config/` ab, z. B. als `config/cert.p12`.

2. Legen Sie die Laufzeitkonfiguration in `config/.env` ab. 


## Verwendung

Führen Sie den folgenden Befehl aus, um den AuthZ-Workflow zu starten:

```bash
python -m app.app.client
```

Dabei ist `sample_metadata.insurantId` durch eine gültige Versicherten-ID zu ersetzen. 

### Ablauf
1. Der AuthZ-Workflow der ePA 3.x wird initiiert.
2. Nach erfolgreicher Authentifizierung wird eine Test-MIO-Datei aus `app/data/examples/documents/REAL_EXAMPLE_1_KBV_PR_MIO_DIGA_Bundle.xml` in die Akte geschrieben.

## Fehlerbehandlung

Bei Problemen überprüfen Sie bitte:
- Liegt die `.p12`-Datei im Verzeichnis `config/`?
- Ist `config/.env` vorhanden und vollständig befüllt?
- Ist die Versicherten-ID gültig und die restlichen Metadaten korrekt?
- Sind alle Abhängigkeiten erfolgreich installiert worden?
- Ist der SMC-B PIN verifiziert?

# License from fbeta GmbH

This work is provided by fbeta GmbH and licensed under the Creative Commons Attribution-NoDerivatives 4.0 International License.

For more information about the license, visit:
https://creativecommons.org/licenses/by-nd/4.0/

© fbeta GmbH. All rights reserved.

# Kontakt

Bei Fragen melden Sie sich gerne per Mail an epa@fbeta.de.