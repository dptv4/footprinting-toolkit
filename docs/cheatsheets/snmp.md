# SNMP cheatsheet

Enumeración autorizada de SNMP (**UDP/161**). UDP puede dar **falsos negativos** — sube `--retries`.

## Toolkit

```bash
python3 main.py snmp 10.10.10.10 --dry-run
python3 modules/snmp_enum.py 10.10.10.10 --dry-run
python3 main.py snmp 10.10.10.10 --communities comms.txt --version 2c --retries 3
python3 main.py snmp 10.10.10.10 --oids 1.3.6.1.2.1.1,1.3.6.1.2.1.25.1.1.0
```

Flags: `target`, `-t/--target`, `--port` (def. 161), `--timeout`, `--retries`, `--dry-run`, `--latest`, `-o/--output`, `--communities`, `--version 1|2c|3`, `--oids`.

Si no pasas `--communities`, se usan: `public`, `private`, `manager`.

## Checks

1. `onesixtyone -c COMMUNITIES TARGET`
2. `snmpwalk -v2c/-v1 -c <community> TARGET` → guarda walk completo en `reports/`
3. OIDs interesantes (`sysDescr/Name/Contact/Location/UpTime`, ifTable, procesos, software, TCP, users Windows) + `--oids`
4. `braa <community>@TARGET:.1.3.6.*` (si está instalado)
5. SNMPv3 `snmpwalk -v3 -l noAuthNoPriv`
6. `nmap -sU -p161 --script snmp-info,snmp-sysdescr,snmp-processes` (requiere root)

Tabla rich: community, versión, acceso ro/rw (deducido con `snmpset` de tipo incorrecto sin cambiar valor), sysDescr.

**Findings:** community `public`/`private`, acceso de escritura, v3 sin auth.

## Comandos manuales

```bash
onesixtyone -c communities.txt <T>
snmpwalk -v2c -c public <T>
snmpget -v2c -c public <T> 1.3.6.1.2.1.1.1.0
braa public@<T>:.1.3.6.*
snmpwalk -v3 -l noAuthNoPriv <T>
sudo nmap -sU -p161 --script snmp-info,snmp-sysdescr,snmp-processes <T>
```
