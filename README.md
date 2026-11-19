# footprinting-toolkit

Toolkit de **enumeración / footprinting** en Python 3.11+ para reconocimiento autorizado de servicios y superficies de red. Entrada unificada vía `main.py` o ejecución directa de cada módulo.

> **Disclaimer:** Usa esta herramienta **únicamente** sobre sistemas, redes y dominios para los que tengas autorización explícita por escrito. El uso no autorizado puede ser ilegal. Este proyecto es solo para enumeración: **no** incluye explotación ni fuerza bruta de credenciales.

## Requisitos

- Python 3.11+
- Dependencias: ver `requirements.txt` (`rich`, `dnspython`, `impacket`, `pymysql`, …)
- Herramientas opcionales en PATH (`nmap`, …): si faltan, el módulo avisa con rich y salta ese check

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Estructura

```text
footprinting-toolkit/
├── main.py                 # Subcomandos auto-descubiertos: modules/*_enum.py
├── core/
│   ├── runner.py           # run_cmd, dry-run, tool/root checks
│   └── parser.py           # reports JSON/MD, --latest, nmap ports, tables
├── modules/
│   └── ftp_enum.py         # Módulo de referencia FTP
├── reports/                # Salida generada (no se versiona)
├── docs/
│   └── cheatsheets/
├── requirements.txt
├── LICENSE                 # MIT
├── .gitignore
└── README.md
```

Cada módulo expone `register_parser(parser)` y `run(args)`. `main.py` solo descubre `*_enum.py` y llama a esas dos funciones (defaults en una única fuente de verdad).

## Uso

```bash
# Vía main.py (subcommand = nombre sin _enum)
python3 main.py ftp 10.10.10.10 --dry-run
python3 main.py ftp -t 10.10.10.10 --port 21

# Directo
python3 modules/ftp_enum.py 10.10.10.10 --dry-run
python3 modules/ftp_enum.py -t 10.10.10.10 --latest
```

Flags comunes (definidos en `register_parser`): `target` posicional, `-t`/`--target`, `--latest`, más flags del módulo (`--port`, `--dry-run`, `--timeout`, `-o`/`--output`).

### Módulo `ftp`

- Banner grabbing TCP
- Login anónimo (`ftplib`) + `LIST`
- `nmap --script ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor`
- Inferencia de escritura anónima solo desde permisos de `LIST` (sin subir ni crear archivos)

## Core

- `run_cmd` / `--dry-run`, `require_tools`, `check_root`
- `save_report` / `load_latest`, `render_table`, `extract_open_ports`

## Licencia

MIT — ver [LICENSE](LICENSE).
