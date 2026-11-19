# Oracle TNS cheatsheet

Enumeración autorizada de **Oracle TNS (1521)**. El módulo **no** prueba credenciales por defecto.

## Toolkit

```bash
python3 main.py oracle 10.10.10.10 --dry-run
python3 modules/oracle_enum.py 10.10.10.10 --dry-run
python3 main.py oracle 10.10.10.10 --sid ORCL
python3 main.py oracle 10.10.10.10 --sid-wordlist sids.txt
```

Flags: `target`, `-t/--target`, `--port` (def. 1521), `--timeout`, `--dry-run`, `--latest`, `-o/--output`, `--sid`, `--sid-wordlist`.

## Checks del módulo

1. `nmap -sV -p1521 --script oracle-tns-version`
2. `tnscmd10g version|status -h TARGET -p PORT` → parsea versión, SID, SERVICE_NAME, listeners  
   - **finding** si el status responde sin auth / listener sin password
3. SID enum **solo** con `--sid-wordlist`: `odat sidguesser … --sids-file` (fallback `nmap oracle-sid-brute`)
4. `--sid`: sonda informativa (odat/nmap) de que el SID responde

## Comandos manuales

```bash
nmap -Pn -sV -p1521 --script oracle-tns-version <T>
tnscmd10g version -h <T> -p 1521
tnscmd10g status -h <T> -p 1521
odat sidguesser -s <T> -p 1521 --sids-file sids.txt
nmap -p1521 --script oracle-sid-brute --script-args oracle-sid-brute.sidfile=sids.txt <T>
```

## Credenciales por defecto (solo referencia manual)

El toolkit **no** las prueba automáticamente. Si el alcance lo permite, revisar manualmente (ejemplos históricos):

| Usuario | Password (histórico) |
|---------|----------------------|
| scott | tiger |
| system | manager |
| sys | change_on_install |
| dbsnmp | dbsnmp |
| outln | outln |

Usar solo con autorización explícita; preferir cuentas aportadas por el cliente frente a diccionarios.
