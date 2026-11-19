# footprinting-toolkit

Toolkit de **enumeración / footprinting** autorizado. Solo recolección pasiva o activa de información pública o permitida; **no** incluye explotación ni fuerza bruta de credenciales.

> **Disclaimer:** Usa esta herramienta únicamente sobre sistemas y dominios para los que tengas autorización explícita. El uso no autorizado puede ser ilegal.

## Requisitos

- Python 3.11+
- Dependencias típicas: `argparse` (stdlib) + `rich`

## Estructura

```text
footprinting-toolkit/
├── main.py                 # Entrada unificada: python3 main.py <modulo>
├── modules/
│   └── <servicio>_enum.py  # Módulos (dns_enum, http_enum, …)
├── reports/                # Salida generada (no se versiona)
├── requirements.txt
├── .gitignore
└── README.md
```

Los módulos se nombran `<servicio>_enum.py` para evitar choques con librerías (`dns`, `enum`, etc.).

## Uso

### Vía `main.py`

```bash
python3 main.py dns_enum
python3 main.py dns_enum -t example.com
python3 main.py dns_enum example.com
python3 main.py dns_enum --latest
```

### Ejecución directa del módulo

```bash
python3 modules/dns_enum.py example.com
python3 modules/dns_enum.py -t example.com
python3 modules/dns_enum.py --latest
```

Ambas vías comparten la misma función `register_parser(parser)` (valores por defecto y flags en una sola fuente de verdad): `target` posicional opcional, `-t`/`--target` y `--latest`.

## Alcance

- Enumeración y footprinting solamente
- Sin exploits, sin fuerza bruta de credenciales
