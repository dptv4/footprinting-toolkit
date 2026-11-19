# IMAP / POP3 cheatsheet

Enumeración autorizada de **IMAP (143/993)** y **POP3 (110/995)**. **No** intenta login anónimo; LIST/STAT solo con `--user` y `--password` explícitos.

## Toolkit

```bash
python3 main.py mail 10.10.10.10 --dry-run
python3 modules/mail_enum.py 10.10.10.10 --dry-run
python3 main.py mail 10.10.10.10 --protocol imap
python3 main.py mail 10.10.10.10 --protocol pop3 --ports 110,995
python3 main.py mail 10.10.10.10 --user alice --password 'Secret'
```

Flags: `target`, `-t/--target`, `--port`, `--ports`, `--protocol imap|pop3|all`, `--timeout`, `--dry-run`, `--latest`, `-o/--output`, `--user`, `--password`.

## Checks

Por cada puerto:
1. Banner (SSL en 993/995)
2. Capabilities: IMAP `a1 CAPABILITY` / POP3 `CAPA`  
   - **finding** si LOGIN/USER sin TLS (`LOGINDISABLED` ausente) o sin STARTTLS/STLS (puertos cleartext)
3. TLS: `openssl s_client` (`-connect` en 993/995, `-starttls imap|pop3` en 143/110) → CN, SAN, emisor, fechas, protocolo/cipher  
   - **finding** si cert caducado o autofirmado

Global:
4. `nmap -sV -p110,143,993,995 --script imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info`
5. Auth opcional: IMAP `LIST` / POP3 `STAT` solo con credenciales explícitas

## Comandos manuales

```bash
openssl s_client -connect <T>:993 -servername <T>
openssl s_client -starttls imap -connect <T>:143
openssl s_client -starttls pop3 -connect <T>:110
nmap -Pn -sV -p110,143,993,995 --script imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info <T>
```
