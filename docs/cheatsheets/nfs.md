# NFS cheatsheet

Enumeración autorizada de NFS/RPC (puertos **111** rpcbind, **2049** nfs). Sin escritura en exports.

## Toolkit

```bash
python3 main.py nfs 10.10.10.10 --dry-run
python3 modules/nfs_enum.py 10.10.10.10 --dry-run
python3 main.py nfs 10.10.10.10 --port 2049
python3 main.py nfs --latest
python3 main.py nfs 10.10.10.10 --mount-check   # requiere root; solo lectura
```

Flags: `target`, `-t/--target`, `--port` (def. 2049), `--timeout`, `--dry-run`, `--latest`, `-o/--output`, `--mount-check`.

## Checks del módulo

1. `nmap -p111,2049 -sV --script rpcinfo,nfs-ls,nfs-showmount,nfs-statfs`
2. `rpcinfo -p TARGET` → **finding** si aparecen `nfs`, `mountd`, `nlockmgr`
3. `showmount -e TARGET` → parsea exports (`path`, hosts, `everyone`); **finding** si `*` / everyone
4. `--mount-check` (off por defecto): con root, `mount -t nfs -o ro,nolock`, `ls -ln`, `umount` siempre en `finally` (no escribe)

`--latest` recupera target/puertos abiertos del último reporte **discovery**.

## Comandos manuales útiles

```bash
nmap -Pn -p111,2049 -sV --script rpcinfo,nfs-ls,nfs-showmount,nfs-statfs <T>
rpcinfo -p <T>
showmount -e <T>
# Solo lectura, con root:
mount -t nfs -o ro,nolock <T>:/export /mnt/nfs
ls -ln /mnt/nfs
umount /mnt/nfs
```

## Hallazgos típicos

| Señal | Por qué importa |
|-------|-----------------|
| nfs/mountd/nlockmgr en rpcinfo | Servicios NFS expuestos vía RPC |
| Export a `*` / everyone | Montaje desde cualquier host |
| UIDs numéricos en `ls -ln` | Squash/no_root_squash / mapeo de privilegios |
