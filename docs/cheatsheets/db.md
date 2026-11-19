# MySQL / MSSQL cheatsheet

Enumeración autorizada de **MySQL (3306)** y **MSSQL (1433 + 1434/udp SQL Browser)**.  
Por defecto **sin autenticación**. Lo autenticado exige `--user` / `--password`. Sin fuerza bruta ni `xp_cmdshell`.

## Toolkit

```bash
python3 main.py db 10.10.10.10 --dry-run
python3 modules/db_enum.py 10.10.10.10 --dry-run
python3 main.py db 10.10.10.10 --engine mysql
python3 main.py db 10.10.10.10 --engine mssql --port 1433
python3 main.py db 10.10.10.10 --engine mysql --user root --password 'Secret'
python3 main.py db 10.10.10.10 --engine mssql --user sa --password 'Secret' --domain CORP
```

Flags: `target`, `-t/--target`, `--port`, `--timeout`, `--dry-run`, `--latest`, `-o/--output`, `--engine mysql|mssql|all`, `--user`, `--password`, `--domain`.

## MySQL

1. `nmap -sV -p3306 --script mysql-info,mysql-empty-password` (+ `mysql-variables,mysql-audit` con creds)
2. Handshake TCP sin auth → versión
3. Un solo intento `root` / contraseña vacía (misconfiguración, no brute force)
4. Con creds: `SELECT version()`, `SHOW DATABASES`, `SELECT user,host FROM mysql.user`, `SHOW GRANTS`

## MSSQL

1. `nmap -sV -p1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password` → hostname/dominio/OS
2. `nmap -sU -p1434 --script ms-sql-info` (root; instancias nombradas)
3. Con creds: impacket TDS / `impacket-mssqlclient` → `@@version`, `sys.databases`, `sys.server_principals` (sin xp_cmdshell)

## Comandos manuales

```bash
nmap -Pn -sV -p3306 --script mysql-info,mysql-empty-password <T>
nmap -Pn -sV -p1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password <T>
sudo nmap -sU -p1434 --script ms-sql-info <T>
impacket-mssqlclient 'user:pass@host' -q 'SELECT @@version'
```
