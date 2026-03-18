# devid

`dev-ID` e' una utility in C ANSI per Windows/MinGW32 che legge un file di configurazione nel formato:

```text
IP=192.168.0.0->192.168.0.0/255.255.255.0 index=7 devname=LAN
```

e produce una scansione multi-thread con:

- un thread per ogni rete univoca dedotta dal file di configurazione
- deduplica automatica delle subnet duplicate
- probing attivo ICMP, TCP connect e UDP responsive-check
- CSV finale con separatore `;` e qualificatore di testo `"..."`
- log unico condiviso tra tutti i thread
- reverse DNS, MAC address quando risolvibile, vendor da file OUI locale e lookup online opzionale
- stima del tipo host e OS in base a TTL e servizi rilevati

## Modalita' di lavoro

Il motore usa una combinazione pragmatica di tecniche a basso livello Windows:

- `SendARP` per MAC address sui segmenti raggiungibili a layer 2
- `IcmpSendEcho` per host discovery e TTL
- socket non bloccanti TCP per rilevare porte aperte
- socket UDP con payload di probe per rilevare servizi responsivi
- `WinHTTP` opzionale per arricchimento vendor online (`--vendor-online`)

## Output

### CSV

Il CSV include questi campi:

```text
"timestamp";"scope";"if_index";"network";"mask";"anchor_ip";"ip";"hostname";"alive";"reachability";"rtt_ms";"ttl";"mac";"vendor";"vendor_source";"type";"os";"tcp_services";"udp_services"
```

### Log

Il log registra:

- avvio e fine scan globale
- start/completion di ogni scope
- host trovati con reachability, servizi TCP/UDP e vendor

## Build

```powershell
mingw32-make
```

## Uso rapido

```powershell
.\netscope-passive.exe --config examples\targets.conf --csv report.csv --log scan.log
```

## Uso con tuning porte e timeout

```powershell
.\netscope-passive.exe --config examples\targets.conf --csv report.csv --log scan.log --tcp-ports 22,80,443,445,3389,8080,8443 --udp-ports 53,123,161 --icmp-timeout-ms 75 --tcp-timeout-ms 60 --udp-timeout-ms 75
```

## Lookup vendor online

```powershell
.\netscope-passive.exe --config examples\targets.conf --csv report.csv --log scan.log --vendor-online
```

## Note pratiche

- Il MAC address non e' sempre ottenibile su reti non direttamente raggiungibili a layer 2.
- Il lookup vendor online e' opzionale per evitare dipendenze di rete e limiti dell'API pubblica.
- La rilevazione UDP e' basata su risposta effettiva: se un servizio UDP non risponde al probe, il tool non lo marca come attivo.
- Su scope molto grandi i tempi di scansione crescono rapidamente; il tuning di porte e timeout e' importante.

## Struttura

- `src/config.c`: parser del file configurazione
- `src/passive.c`: motore di scansione, thread per rete, log, vendor lookup
- `src/report.c`: writer CSV `;` + `"..."`
- `src/main.c`: CLI e orchestrazione
- `examples/targets.conf`: esempio completo
- `examples/targets-mini.conf`: esempio piccolo per test rapido

## Licenza

MIT.
