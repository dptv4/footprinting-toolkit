# footprinting-toolkit

Toolkit de **enumeración / footprinting** en Python 3.11+ para reconocimiento autorizado de servicios y superficies de red. Entrada unificada vía `main.py` o ejecución directa de cada módulo.

> **Disclaimer:** Usa esta herramienta **únicamente** sobre sistemas, redes y dominios para los que tengas autorización explícita por escrito. El uso no autorizado puede ser ilegal. Este proyecto es solo para enumeración: **no** incluye explotación ni fuerza bruta de credenciales.

## Requisitos

- Python 3.11+
- Dependencias: ver `requirements.txt` (`rich`, `dnspython`, `impacket`, `pymysql`, …)
- Herramientas opcionales en PATH (`nmap`, `dig`, `openssl`, `onesixtyone`, `snmpwalk`, …): si faltan, el módulo avisa con rich y salta ese check

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
│   ├── ftp_enum.py | smb_enum.py | nfs_enum.py
│   ├── dns_enum.py | smtp_enum.py | mail_enum.py | snmp_enum.py
├── docs/cheatsheets/  smb.md nfs.md dns.md smtp.md mail.md snmp.md
├── reports/
├── requirements.txt | LICENSE | .gitignore | README.md
```

Cada módulo: `register_parser(parser)` + `run(args)`. Checks `{check, command, status, summary, raw}`.

## Uso

```bash
python3 main.py snmp 10.10.10.10 --dry-run
python3 modules/snmp_enum.py 10.10.10.10 --dry-run
python3 main.py snmp 10.10.10.10 --communities comms.txt --retries 3
python3 main.py mail 10.10.10.10 --protocol imap
python3 main.py dns 10.10.10.10 --domain corp.local
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
| `snmp` | 161/udp | communities, walks, OIDs; [cheatsheet](docs/cheatsheets/snmp.md) |

## Licencia

MIT — ver [LICENSE](LICENSE).
