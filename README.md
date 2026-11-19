# footprinting-toolkit

Toolkit de **enumeración / footprinting** en Python 3.11+ para reconocimiento autorizado de servicios y superficies de red. Entrada unificada vía `main.py` o ejecución directa de cada módulo.

> **Disclaimer:** Usa esta herramienta **únicamente** sobre sistemas, redes y dominios para los que tengas autorización explícita por escrito. El uso no autorizado puede ser ilegal. Este proyecto es solo para enumeración: **no** incluye explotación ni fuerza bruta de credenciales.

## Requisitos

- Python 3.11+
- Dependencias: ver `requirements.txt` (`rich`, `dnspython`, `impacket`, `pymysql`, …)
- Herramientas opcionales en PATH (`nmap`, `dig`, `openssl`, `smbclient`, …): si faltan, el módulo avisa con rich y salta ese check

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
│   ├── dns_enum.py
│   └── smtp_enum.py
├── reports/
├── docs/cheatsheets/
│   ├── smb.md
│   ├── nfs.md
│   ├── dns.md
│   └── smtp.md
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
python3 main.py smtp 10.10.10.10 --dry-run
python3 main.py smtp 10.10.10.10 --userlist users.txt --method all

python3 modules/smtp_enum.py 10.10.10.10 --dry-run
python3 modules/dns_enum.py 10.10.10.10 --domain corp.local
```

Flags comunes: `target`, `-t/--target`, `--port`, `--timeout`, `--dry-run`, `--latest`, `-o/--output`.

### Módulos

| Módulo | Puertos | Notas |
|--------|---------|--------|
| `ftp` | 21 | Banner, anónimo, nmap FTP |
| `smb` | 139/445 | Null/guest/auth; [cheatsheet](docs/cheatsheets/smb.md) |
| `nfs` | 111/2049 | showmount, `--mount-check`; [cheatsheet](docs/cheatsheets/nfs.md) |
| `dns` | 53 | `--domain` obligatorio salvo dry-run; [cheatsheet](docs/cheatsheets/dns.md) |
| `smtp` | 25/465/587 | Banner/EHLO, open-relay sin DATA, `--userlist`; [cheatsheet](docs/cheatsheets/smtp.md) |

## Licencia

MIT — ver [LICENSE](LICENSE).
