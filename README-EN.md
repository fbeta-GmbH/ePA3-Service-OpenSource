# ePA 3.x Integration

This project implements:
- the AuthZ workflow for the electronic patient record (ePA) 3.x.
- writing a Medical Information Object (MIO) to the electronic patient record.

## Prerequisites

- Python 3.8 or higher
- PowerShell / Bash
- TI-Terminal-CA Certificate

## Installation

To install all necessary dependencies, run the script `install_dependencies.sh` (macOS/Linux) or `install_dependencies.ps1` (Windows):

**macOS/Linux:**
```bash
./install_dependencies.sh
```

**Windows:**
```powershell
./install_dependencies.ps1
```

## Environment Configuration

1. Copy the `.env.template` file to `.env`:
   ```bash
   cp app/.env.template app/.env
   ```

2. Fill in the following environment variables in the `.env` file:

### Basic Configuration
- `EPA_ENVIRONMENT`: ePA environment (e.g., `RU`, `RT`, `PROD`)
- `DEFAULT_EPA_PROVIDER_ID`: ID of the ePA account provider (e.g., `1` for IBM, `2` for Bitmarck Technik / RISE)
- `USER_AGENT`: User Agent string for HTTP requests
- `KONNEKTOR_URL`: URL of the connector

### DiGA Identification
The following variables are used to create the Author string:
- `DIGA_NAME`: Name of your DiGA (name of the prescription unit)
- `DIGA_MANUFACTURER`: Name of the DiGA manufacturer
- `SW_ADDITION_1`: Software designation addition 1 (optional)
- `SW_ADDITION_2`: Software designation addition 2 (optional)
- `SW_ADDITION_3`: Software designation addition 3 (optional)

Alternatively, you can set the complete Author string directly:
- `AUTHOR`: Complete Author string (optional, overrides individual DiGA variables)

### Connector Workspace
- `MANDANT_ID`: ID of the configured client in the connector
- `CLIENT_SYSTEM_ID`: ID of the configured client system in the connector
- `WORKPLACE_ID`: ID of the configured workplace in the connector

### Logging
- `LOG_LEVEL`: Logging level (INFO, DEBUG, ERROR, etc.)

## Configuration

1. Split the TI-Terminal-CA certificate into two separate files:
    - `cert.pem`: The certificate
    - `key.pem`: The private key

    If you have a .p12 file, you can use OpenSSL:

    ```bash
    # Extract certificate
    openssl pkcs12 -in certificate.p12 -clcerts -nokeys -out cert.pem

    # Extract private key
    openssl pkcs12 -in certificate.p12 -nocerts -nodes -out key.pem
    ```

    You will be prompted for the import password for the .p12 file.

2. Place both files in the `app/data` directory.

## Usage

Run the following command to start the AuthZ workflow:

```bash
python -m app.app.client
```

Replace `sample_metadata.insurantId` with a valid insured person ID.

### Process Flow
1. The ePA 3.x AuthZ workflow is initiated.
2. After successful authentication, a test MIO file (`REAL_EXAMPLE_1_KBV_PR_MIO_DIGA_Bundle.xml`) is written to the record.

## Troubleshooting

If you encounter issues, please check:
- Are the certificate files correctly placed in the `app/data` directory?
- Is the insured person ID valid and are the remaining metadata correct?
- Have all dependencies been successfully installed?
- Is the SMC-B PIN verified?

# License from fbeta GmbH

This work is provided by fbeta GmbH and licensed under the Creative Commons Attribution-NoDerivatives 4.0 International License.

For more information about the license, visit:
https://creativecommons.org/licenses/by-nd/4.0/

© fbeta GmbH. All rights reserved.

# Contact

For questions, please contact us at epa@fbeta.de.