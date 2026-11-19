# SMTP cheatsheet

Enumeración autorizada de SMTP (**25 / 465 / 587**). Sin fuerza bruta de credenciales; el probe de open relay **no envía DATA**.

## Toolkit

```bash
python3 main.py smtp 10.10.10.10 --dry-run
python3 modules/smtp_enum.py 10.10.10.10 --dry-run
python3 main.py smtp 10.10.10.10 --port 25
python3 main.py smtp 10.10.10.10 --userlist users.txt --method all --delay 0.2
python3 main.py smtp 10.10.10.10 --method vrfy --userlist users.txt
```

Flags: `target`, `-t/--target`, `--port` (def. 25), `--timeout`, `--dry-run`, `--latest`, `-o/--output`, `--userlist`, `--method vrfy|expn|rcpt|all`, `--delay`, `--ehlo-host`.

## Checks del módulo

1. Banner TCP + `EHLO` (extensiones STARTTLS/AUTH/VRFY/EXPN/SIZE…) → **finding** si el banner revela software/versión; siempre `QUIT`
2. `nmap -p25,465,587 -sV --script smtp-commands,smtp-open-relay,smtp-ntlm-info`
3. Open relay: `MAIL FROM` / `RCPT TO` con dominios externos de ejemplo — **sin DATA**
4. User enum solo con `--userlist`: VRFY / EXPN / RCPT (`--method`, `--delay` def. 0.2s). Antes comprueba si VRFY/EXPN están habilitados
5. Si hay STARTTLS (o puerto 465): `openssl s_client` para el certificado

## Comandos manuales útiles

```bash
nc -nv <T> 25
# EHLO footprinting.local
nmap -Pn -p25,465,587 -sV --script smtp-commands,smtp-open-relay,smtp-ntlm-info <T>
openssl s_client -starttls smtp -connect <T>:25
# Open relay (sin DATA):
# MAIL FROM:<probe@example.com>
# RCPT TO:<probe@example.org>
# RSET / QUIT
```

## Hallazgos típicos

| Señal | Por qué importa |
|-------|-----------------|
| Banner con versión | Fingerprint (Postfix/Exim/…) |
| Open relay (MAIL/RCPT 250) | Abuso de retransmisión |
| VRFY/EXPN/RCPT hits | Enumeración de buzones |
| NTLM info / cert CN | Identidad del servicio |
