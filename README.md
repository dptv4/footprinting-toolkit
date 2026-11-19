# footprinting-toolkit

Toolkit de **enumeración / footprinting** en Python 3.11+ para reconocimiento autorizado de servicios y superficies de red. Entrada unificada vía `main.py` o ejecución directa de cada módulo.

> **Disclaimer:** Usa esta herramienta **únicamente** sobre sistemas, redes y dominios para los que tengas autorización explícita por escrito. El uso no autorizado puede ser ilegal. Este proyecto es solo para enumeración: **no** incluye explotación ni fuerza bruta de credenciales.

## Requisitos

- Python 3.11+
- Dependencias: ver `requirements.txt` (`rich`, `dnspython`, `impacket`, `pymysql`, …)
- Herramientas opcionales en PATH (`nmap`, `tnscmd10g`, `odat`, …)

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
├── modules/
│   ├── ftp_enum.py | smb_enum.py | nfs_enum.py | dns_enum.py
│   ├── smtp_enum.py | mail_enum.py | snmp_enum.py | db_enum.py
│   └── oracle_enum.py
├── docs/cheatsheets/  … oracle.md
├── reports/
├── requirements.txt | LICENSE | .gitignore | README.md
```

Cada módulo: `register_parser(parser)` + `run(args)`. Checks `{check, command, status, summary, raw}`.

## Uso

```bash
python3 main.py oracle 10.10.10.10 --dry-run
python3 modules/oracle_enum.py 10.10.10.10 --dry-run
python3 main.py oracle 10.10.10.10 --sid ORCL --sid-wordlist sids.txt
```

### Módulos

| Módulo | Puertos | Notas |
|--------|---------|--------|
| `ftp` | 21 | Banner, anónimo, nmap FTP |
| `smb` | 139/445 | [cheatsheet](docs/cheatsheets/smb.md) |
| `nfs` | 111/2049 | [cheatsheet](docs/cheatsheets/nfs.md) |
| `dns` | 53 | [cheatsheet](docs/cheatsheets/dns.md) |
| `smtp` | 25/465/587 | [cheatsheet](docs/cheatsheets/smtp.md) |
| `mail` | 110/143/993/995 | [cheatsheet](docs/cheatsheets/mail.md) |
| `snmp` | 161/udp | [cheatsheet](docs/cheatsheets/snmp.md) |
| `db` | 3306 / 1433 / 1434/udp | [cheatsheet](docs/cheatsheets/db.md) |
| `oracle` | 1521 | TNS/listener/SID; [cheatsheet](docs/cheatsheets/oracle.md) |

## Licencia

MIT — ver [LICENSE](LICENSE).
