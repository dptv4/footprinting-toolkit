# Remote management cheatsheet

Enumeración de **SSH, RDP, WinRM, RPC/WMI, rsync, r-services**. Sin fuerza bruta; WinRM auth solo con `--user`/`--password`.

## Toolkit

```bash
python3 main.py remote 10.10.10.10 --dry-run
python3 modules/remote_enum.py 10.10.10.10 --dry-run
python3 main.py remote 10.10.10.10 --services ssh,rdp
python3 main.py remote 10.10.10.10 --services winrm --user alice --password 'Secret'
python3 main.py remote --latest   # omite servicios cuyos puertos no estén en discovery
```

Flags: `target`, `-t/--target`, `--port`, `--ports`, `--services`, `--timeout`, `--dry-run`, `--latest`, `-o/--output`, `--user`, `--password`.

## Servicios

| Servicio | Puertos | Checks clave |
|----------|---------|--------------|
| ssh | 22 | banner, `ssh-audit`, nmap `ssh2-enum-algos,ssh-hostkey,ssh-auth-methods` |
| rdp | 3389 | nmap `rdp-enum-encryption,rdp-ntlm-info` (NLA / hostname / dominio) |
| winrm | 5985/5986 | POST `/wsman` (401/405), nmap `-sV`, `nxc winrm` con creds |
| rpc | 135 | nmap `msrpc-enum`, `impacket-rpcdump` (MS-RPRN / MS-EFSR) |
| rsync | 873 | nmap `rsync-list-modules`, `rsync --list-only` (sin descargar) |
| rservices | 512-514 | nmap `-sV`, `rusers -l` / `rwho` |

## Hallazgos típicos

- SSH: password auth, algos débiles, protocolo 1
- RDP: NLA desactivado, NTLM info
- WinRM: listener activo, acceso con creds
- RPC: MS-RPRN / MS-EFSR
- rsync: módulos listables
- r-services: puertos abiertos / rusers-rwho
