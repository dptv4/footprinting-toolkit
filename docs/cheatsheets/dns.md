# DNS cheatsheet

Enumeración autorizada de DNS (**puerto 53**). `TARGET` es el **servidor DNS**; el dominio va en `--domain`.

## Toolkit

```bash
python3 main.py dns 10.10.10.10 --dry-run
python3 modules/dns_enum.py 10.10.10.10 --dry-run
python3 main.py dns 10.10.10.10 --domain corp.local
python3 main.py dns 10.10.10.10 --domain corp.local --nameserver 10.10.10.10
python3 main.py dns 10.10.10.10 --domain corp.local --wordlist subs.txt --threads 20
python3 main.py dns 10.10.10.10 --domain corp.local --reverse 10.10.10.0/28
```

Flags: `target`, `-t/--target`, `--port` (def. 53), `--timeout`, `--dry-run`, `--latest`, `-o/--output`, `--domain` (obligatorio salvo dry-run), `--nameserver` (def. TARGET), `--wordlist`, `--threads`, `--reverse CIDR`.

## Checks del módulo

1. `dig @NS DOMAIN` → NS, MX, TXT, SOA, A, AAAA, ANY (tabla por tipo)
2. `dig @NS version.bind CHAOS TXT` (+ `hostname.bind`) → **finding** si revela versión
3. `dig AXFR @<ns> DOMAIN` (cada NS + TARGET) → **finding CRÍTICO** si funciona
4. Subdominios con `--wordlist` vía **dnspython** + `ThreadPoolExecutor` (`--threads` def. 20)
5. `--reverse CIDR` con `dig -x`
6. `nmap -sU -sT -p53 --script dns-nsid,dns-recursion,dns-zone-transfer --script-args dns-zone-transfer.domain=DOMAIN`  
   (sin root: solo `-sT`)
7. Recursión abierta (probe externo) → **finding**

## Comandos manuales útiles

```bash
dig @<NS> <DOMAIN> NS MX TXT SOA A AAAA ANY
dig @<NS> version.bind CHAOS TXT
dig @<NS> hostname.bind CHAOS TXT
dig AXFR @<NS> <DOMAIN>
dig @<NS> example.com A +recurse
dig @<NS> -x 10.10.10.5
nmap -sU -sT -p53 --script dns-nsid,dns-recursion,dns-zone-transfer \
  --script-args dns-zone-transfer.domain=<DOMAIN> <NS>
```

## Hallazgos típicos

| Señal | Por qué importa |
|-------|-----------------|
| version.bind | Fingerprint del software DNS |
| AXFR OK | Filtración completa de zona |
| Recursión abierta | Amplificación / uso como resolver |
| NSID | Identificador de instancia |
