# footprinting-toolkit

Toolkit de **enumeración / footprinting** en Python 3.11+ para reconocimiento autorizado de servicios y superficies de red. Entrada unificada vía `main.py` o ejecución directa de cada módulo.

> **Disclaimer:** Usa esta herramienta **únicamente** sobre sistemas, redes y dominios para los que tengas autorización explícita por escrito. El uso no autorizado puede ser ilegal. Este proyecto es solo para enumeración: **no** incluye explotación ni fuerza bruta de credenciales.

## Requisitos

- Python 3.11+
- Dependencias: ver `requirements.txt` (`rich`, `dnspython`, `impacket`, `pymysql`, `requests`, …)
- Herramientas opcionales en PATH (`nmap`, `ssh-audit`, `nxc`, `rsync`, …)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Estructura

```text
footprinting-toolkit/
├── main.py
├── core/ runner.py, parser.py
├── modules/  … remote_enum.py
├── docs/cheatsheets/  … remote.md
├── reports/
├── requirements.txt | LICENSE | .gitignore | README.md
```

Cada módulo: `register_parser(parser)` + `run(args)`. Checks `{check, command, status, summary, raw}`.

## Uso

```bash
python3 main.py remote 10.10.10.10 --dry-run
python3 modules/remote_enum.py 10.10.10.10 --dry-run
python3 main.py remote 10.10.10.10 --services ssh,rdp,winrm
python3 main.py remote --latest
```

### Módulos

| Módulo | Puertos | Notas |
|--------|---------|--------|
| `ftp` | 21 | Banner, anónimo |
| `smb` | 139/445 | [smb.md](docs/cheatsheets/smb.md) |
| `nfs` | 111/2049 | [nfs.md](docs/cheatsheets/nfs.md) |
| `dns` | 53 | [dns.md](docs/cheatsheets/dns.md) |
| `smtp` | 25/465/587 | [smtp.md](docs/cheatsheets/smtp.md) |
| `mail` | 110/143/993/995 | [mail.md](docs/cheatsheets/mail.md) |
| `snmp` | 161/udp | [snmp.md](docs/cheatsheets/snmp.md) |
| `db` | 3306/1433/1434 | [db.md](docs/cheatsheets/db.md) |
| `oracle` | 1521 | [oracle.md](docs/cheatsheets/oracle.md) |
| `remote` | 22/3389/5985-6/135/873/512-514 | [remote.md](docs/cheatsheets/remote.md) |

## Licencia

MIT — ver [LICENSE](LICENSE).
