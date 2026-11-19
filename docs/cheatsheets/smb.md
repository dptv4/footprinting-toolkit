# SMB cheatsheet

Enumeración autorizada de SMB/CIFS (puertos **139/445**). Sin explotación ni fuerza bruta.

## Toolkit

```bash
python3 main.py smb 10.10.10.10 --dry-run
python3 modules/smb_enum.py 10.10.10.10 --dry-run
python3 main.py smb 10.10.10.10 --port 445
python3 main.py smb 10.10.10.10 --user alice --password 'Secret' --domain CORP
```

Flags: `target`, `-t/--target`, `--port` (def. 445), `--timeout`, `--dry-run`, `--latest`, `-o/--output`, `--user`, `--password`, `--domain`.

## Checks del módulo (orden)

1. `nmap -p139,445 -sV --script smb-os-discovery,smb-protocols,smb2-security-mode,smb2-time`  
   - **finding** si signing no es required o SMBv1 habilitado
2. `smbclient -N -L //TARGET -p PORT` (null session)
3. `smbmap -H TARGET -u '' -p ''` y `smbmap ... -u guest -p ''`
4. `rpcclient -U "" -N TARGET -c "srvinfo;enumdomusers;enumdomgroups;querydispinfo;netshareenumall"`  
   - Extrae usuarios + RIDs
5. `enum4linux-ng -A TARGET` (si está instalado)
6. `nmap --script smb-enum-shares,smb-enum-users` (sesión nula)

Si pasas `--user` / `--password` / `--domain`, se repiten **smbclient** y **smbmap** autenticados.

## Comandos manuales útiles

```bash
nmap -Pn -p139,445 -sV --script smb-os-discovery,smb-protocols,smb2-security-mode,smb2-time <T>
smbclient -N -L //<T>
smbmap -H <T> -u '' -p ''
smbmap -H <T> -u guest -p ''
rpcclient -U "" -N <T> -c "enumdomusers;netshareenumall"
enum4linux-ng -A <T>
nmap -Pn -p139,445 --script smb-enum-shares,smb-enum-users <T>
```

## Hallazgos típicos

| Señal | Por qué importa |
|-------|-----------------|
| Signing not required | Relay / downgrade más viable |
| SMBv1 enabled | Protocolo legado, mayor superficie |
| Null/guest share READ/WRITE | Datos expuestos sin credenciales |
| enumdomusers vía null session | Usuarios/RIDs para pivote (sin spray aquí) |
