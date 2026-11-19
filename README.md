# footprinting-toolkit

Toolkit de **enumeración / footprinting** en Python 3.11+ para reconocimiento autorizado de servicios y superficies de red. Entrada unificada vía `main.py` o ejecución directa de cada módulo.

> **Disclaimer:** Usa esta herramienta **únicamente** sobre sistemas, redes y dominios para los que tengas autorización explícita por escrito. El uso no autorizado puede ser ilegal. Este proyecto es solo para enumeración: **no** incluye explotación ni fuerza bruta de credenciales.

## Requisitos

- Python 3.11+
- Dependencias: ver `requirements.txt` (`rich`, `dnspython`, `impacket`, `pymysql`, …)
- Herramientas opcionales en PATH (`nmap`, `smbclient`, `smbmap`, `rpcclient`, `enum4linux-ng`, `rpcinfo`, `showmount`, …): si faltan, el módulo avisa con rich y salta ese check

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
│   ├── ftp_enum.py
│   ├── smb_enum.py
│   └── nfs_enum.py
├── reports/                # Salida generada (no se versiona)
├── docs/
│   └── cheatsheets/
│       ├── smb.md
│       └── nfs.md
├── requirements.txt
├── LICENSE                 # MIT
├── .gitignore
└── README.md
```

Cada módulo expone `register_parser(parser)` y `run(args)`. `main.py` solo descubre `*_enum.py` y llama a esas dos funciones (defaults en una única fuente de verdad). Cada check del reporte usa `{check, command, status, summary, raw}` con `status` ∈ `ok|fail|skipped|finding`.

## Uso

```bash
# Vía main.py (subcommand = nombre sin _enum)
python3 main.py ftp 10.10.10.10 --dry-run
python3 main.py smb 10.10.10.10 --dry-run
python3 main.py nfs 10.10.10.10 --dry-run
python3 main.py nfs --latest
python3 main.py nfs 10.10.10.10 --mount-check

# Directo
python3 modules/ftp_enum.py 10.10.10.10 --dry-run
python3 modules/smb_enum.py 10.10.10.10 --dry-run
python3 modules/nfs_enum.py 10.10.10.10 --dry-run
```

Flags comunes: `target` posicional, `-t`/`--target`, `--port`, `--timeout`, `--dry-run`, `--latest`, `-o`/`--output`.

### Módulo `ftp`

- Banner grabbing TCP, login anónimo + `LIST`, scripts nmap FTP, write hints solo desde permisos LIST

### Módulo `smb`

- Puertos 139/445 (`--port` def. 445)
- nmap discovery (finding si signing ≠ required o SMBv1)
- `smbclient` / `smbmap` null+guest (y auth opcional con `--user`/`--password`/`--domain`)
- `rpcclient` null enum (usuarios + RIDs), `enum4linux-ng`, nmap `smb-enum-*`
- Cheatsheet: [docs/cheatsheets/smb.md](docs/cheatsheets/smb.md)

### Módulo `nfs`

- Puertos 111/2049 (`--port` def. 2049)
- nmap `rpcinfo,nfs-ls,nfs-showmount,nfs-statfs`
- `rpcinfo -p` (finding si nfs/mountd/nlockmgr) y `showmount -e` (finding si export a `*`/everyone)
- `--mount-check`: montaje RO + `ls -ln` + umount en `finally` (requiere root; no escribe)
- `--latest` recupera puertos abiertos del último reporte discovery
- Cheatsheet: [docs/cheatsheets/nfs.md](docs/cheatsheets/nfs.md)

## Core

- `run_cmd` / `--dry-run`, `require_tools`, `check_root`
- `save_report` / `load_latest`, `render_table`, `extract_open_ports`

## Licencia

MIT — ver [LICENSE](LICENSE).
