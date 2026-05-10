# PCAP Didactic Analyzer

Strumento web didattico per l'analisi di tracce di rete Wireshark, pensato per chi si avvicina per la prima volta all'analisi dei pacchetti.

PCAP Didactic Analyzer e un'applicazione web che permette di caricare file `.pcap` e `.pcapng` esportati da Wireshark e ottenere non solo grafici e statistiche, ma soprattutto spiegazioni in linguaggio naturale di quello che sta accadendo nella rete.

L'obiettivo e rendere l'analisi del traffico di rete accessibile a studenti e principianti, trasformando dati tecnici in contenuti comprensibili, collegati alla teoria del corso di reti di calcolatori.

## Tech stack

- HTML, CSS, JavaScript (vanilla)
- Chart.js per i grafici interattivi
- `@cto.af/pcap-ng-parser` (caricato via ESM CDN) come base per il parsing

## Avvio locale

Apri `index.html` con un web server statico (consigliato).

Esempio con Python:

```bash
python -m http.server 8080
```

Poi visita `http://localhost:8080`.

## Stato attuale

Scheletro base pronto:

- pagina principale con upload `.pcap/.pcapng`
- sezione file di esempio
- area analisi didattica (placeholder)
- grafici iniziali con Chart.js

Nei prossimi step aggiungeremo:

- parsing reale dei pacchetti e protocol detection
- spiegazioni su 3 livelli (cosa vedo, cosa significa, perche e importante)
- grafici basati sui dati del capture
- caricamento effettivo dei sample capture
