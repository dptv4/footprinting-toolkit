# footprinting-toolkit

Toolkit de **enumeración / footprinting** en Python 3.11+ para reconocimiento autorizado de servicios y superficies de red. Entrada unificada vía `main.py` o ejecución directa de cada módulo.

> **Disclaimer:** Usa esta herramienta **únicamente** sobre sistemas, redes y dominios para los que tengas autorización explícita por escrito. El uso no autorizado puede ser ilegal. Este proyecto es solo para enumeración: **no** incluye explotación ni fuerza bruta de credenciales.

## Requisitos

- Python 3.11+
- Dependencias: ver `requirements.txt` (`rich`, `dnspython`, `impacket`, `pymysql`, …)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Estructura prevista

```text
footprinting-toolkit/
├── main.py                 # Entrada unificada: python3 main.py <modulo>
├── core/                   # Utilidades compartidas
├── modules/
│   └── <servicio>_enum.py  # p. ej. dns_enum.py, smb_enum.py
├── reports/                # Salida generada (no se versiona)
├── docs/
│   └── cheatsheets/        # Guías rápidas por servicio
├── requirements.txt
├── LICENSE                 # MIT
├── .gitignore
└── README.md
```

## Uso (previsto)

```bash
# Vía main.py
python3 main.py dns_enum -t example.com

# Directo
python3 modules/dns_enum.py example.com
```

Ambas vías comparten `register_parser(parser)` (misma fuente de verdad para flags y defaults): `target` posicional opcional, `-t`/`--target`, `--latest`.

## Licencia

MIT — ver [LICENSE](LICENSE).
