---
layout: post 
style: fill
title: Rimani aggiornato con foto spettacolari
image: /images/image-of-the-day.webp
tags: [automazione, personalizzazione]
color: dark
---

![Thumbnail]({{ site.url }}/images/image-of-the-day.webp)

Cercavo un modo per avere nuovi sfondi per il mio desktop, e ho pensato che le migliori immagini potessero essere scattate dalla NASA. Costellazioni e galassie a portata di occhio! Quindi mi sono chiesto dove potessi scaricare alcune di queste, magari le più belle, ed ecco che mi imbatto nella loro API per scaricare la "Astronomy Picture Of the Day (APOD)".

Immediatamente ho realizzato 2 script per automatizzare il download sfruttando la loro API. Questo è il risultato!

**NB**: La chiave per usare l'API permette 30 richieste all'ora dallo stesso IP e un totale di 50 richieste massime giornaliere. Se si volesse eccedere questo limite, per questa, o per qualsiasi altra API, bisognerà registrarsi [qui](https://api.nasa.gov/index.html#getting-started){:target="_blank"} per ottenere una chiave da sviluppatore da sostituire alla DEMO_KEY del codice.

{% gist 4c18cacf2acdf4bab98229736c42cdb0 img-of-the-day-download.md %}

## Scripts

### Script per Windows (PowerShell + Task Scheduler)

{% gist 4c18cacf2acdf4bab98229736c42cdb0 NASA-APOD-download.ps1 %}

Per automatizzare il processo fare riferimento a [questa guida](https://www.digitalcitizen.life/how-create-task-basic-task-wizard){:target="_blank"}.

### Script per Linux (Bash + Cron)

{% gist 4c18cacf2acdf4bab98229736c42cdb0 NASA-APOD-download.sh %}

Per automatizzare il processo, fare riferimento a [questa guida](https://askubuntu.com/questions/2368/how-do-i-set-up-a-cron-job){:target="_blank"}.

## BONUS: Bing pic of the day!

Mentre preparavo l'articolo ho scoperto alcuni modi per avere anche l'immagine del giorno di BIng!

### Script per windows 

{% gist 4c18cacf2acdf4bab98229736c42cdb0 BING-image-of-the-day.ps1 %}

### Script per Linux

{% gist 4c18cacf2acdf4bab98229736c42cdb0 BING-image-of-the-day.sh %}
