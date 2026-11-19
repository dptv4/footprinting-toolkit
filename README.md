# footprinting-toolkit

Toolkit de **enumeración / footprinting** en Python 3.11+ para reconocimiento autorizado de servicios y superficies de red. Entrada unificada vía `main.py` o ejecución directa de cada módulo.

> **Disclaimer:** Usa esta herramienta **únicamente** sobre sistemas, redes y dominios para los que tengas autorización explícita por escrito. El uso no autorizado puede ser ilegal. Este proyecto es solo para enumeración: **no** incluye explotación ni fuerza bruta de credenciales.

## Requisitos

- Python 3.11+
- Dependencias: ver `requirements.txt` (`rich`, `dnspython`, `impacket`, `pymysql`, …)
- Herramientas opcionales en PATH (`nmap`, `dig`, `smbclient`, `smbmap`, `rpcclient`, `enum4linux-ng`, `rpcinfo`, `showmount`, …): si faltan, el módulo avisa con rich y salta ese check

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Estructura

```text
footprinting-toolkit/
├── main.py
├── core/
│   ├── runner.py
│   └── parser.py
├── modules/
│   ├── ftp_enum.py
│   ├── smb_enum.py
│   ├── nfs_enum.py
│   └── dns_enum.py
├── reports/
├── docs/cheatsheets/
│   ├── smb.md
│   ├── nfs.md
│   └── dns.md
├── requirements.txt
├── LICENSE
├── .gitignore
└── README.md
```

Cada módulo expone `register_parser(parser)` y `run(args)`. Checks: `{check, command, status, summary, raw}` con `status` ∈ `ok|fail|skipped|finding`.

## Uso

```bash
python3 main.py ftp 10.10.10.10 --dry-run
python3 main.py smb 10.10.10.10 --dry-run
python3 main.py nfs 10.10.10.10 --dry-run
python3 main.py dns 10.10.10.10 --dry-run
python3 main.py dns 10.10.10.10 --domain corp.local

python3 modules/ftp_enum.py 10.10.10.10 --dry-run
python3 modules/smb_enum.py 10.10.10.10 --dry-run
python3 modules/nfs_enum.py 10.10.10.10 --dry-run
python3 modules/dns_enum.py 10.10.10.10 --dry-run
python3 modules/dns_enum.py 10.10.10.10 --domain corp.local --wordlist subs.txt
```

Flags comunes: `target`, `-t/--target`, `--port`, `--timeout`, `--dry-run`, `--latest`, `-o/--output`.

### Módulo `ftp`

Banner, anónimo+LIST, nmap FTP, write hints desde permisos LIST.

### Módulo `smb`

Puertos 139/445; null/guest/auth opcional; shares, users/RIDs. [cheatsheet](docs/cheatsheets/smb.md)

### Módulo `nfs`

Puertos 111/2049; rpcinfo/showmount; `--mount-check` RO. [cheatsheet](docs/cheatsheets/nfs.md)

### Módulo `dns`

Puerto 53; `TARGET` = servidor DNS; `--domain` obligatorio salvo `--dry-run`; dig + CHAOS + AXFR + wordlist (dnspython) + reverse + nmap. [cheatsheet](docs/cheatsheets/dns.md)

## Licencia

MIT — ver [LICENSE](LICENSE).
