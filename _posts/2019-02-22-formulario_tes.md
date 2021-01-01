---
title: Formulario TES @ Politecnico di Torino
style: fill
color: light
image: /images/thumbnail-formulario.webp
tags: [ ingegneria informatica, formulario ]
description: <img src="/images/thumbnail-formulario.webp"> Formulario di Teoria ed Elaborazione dei Segnali al Polito
---

<script type="text/javascript" async
  src="https://cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.5/latest.js?config=TeX-MML-AM_CHTML">
</script>
![Thumbnail]({{ site.url }}/images/thumbnail-formulario.webp)

## Teoria dei segnali

### Esercitazione 1: Energia e Potenza

**Energia** di un segnale:

$$
E(x)=\int_{- \infty}^{\infty}|x(t)|^2dt
$$

**Potenza** di un segnale:

$$
P(x)=\lim _{a \rightarrow \infty} \frac{1}{2a}\int_{- a}^{a}|x(t)|^2dt=\lim _{a \rightarrow \infty} \frac{1}{2a}E(x)​
$$

**Sviluppare una funzione $$z(t)$$ su una base ortonormale** $$\{w1(t), w2(t), …, wn(t)\}$$ significa scrivere $$z(t)$$ come combinazione lineare dei segnali che compongono la base:

$$
z(t)=\sum_{i=1}^n \alpha_i w_i(t) \rightarrow con \space\alpha_i =\langle z,w_i \rangle =\int_{- \infty}^{\infty}z(t) \cdot w_i(t)dt
$$

**Diseguaglianza di Bessel**:

$$
\sum_{i=1}^{n} \langle z,w_i \rangle^2 \le {E(z)} ​
$$

**Procedura di Gram-Schmidt** per trovare la base di vettori ortonormali per il segnale:

| $$\hat{w}_1 = x_1$$                                          | $$w_1=\frac{\hat{w}_1}{\Arrowvert\hat{w}_1\Arrowvert}$$ |
| ------------------------------------------------------------ | ------------------------------------------------------- |
| $$\hat{w}_2 = x_2 - \langle x_2,w_1 \rangle w_1$$            | $$w_2=\frac{\hat{w}_2}{\Arrowvert\hat{w}_2\Arrowvert}$$ |
| $$\hat{w}_3 = x_3 - \langle x_3,w_1 \rangle w_1 - \langle x_3,w_2 \rangle w_2$$ | $$w_3=\frac{\hat{w}_3}{\Arrowvert\hat{w}_3\Arrowvert}$$ |
| $$\hat{w}_4 = x_4 - \langle x_4,w_1 \rangle w_1 - \langle x_4,w_2 \rangle w_2 - \langle x_4,w_3 \rangle w_3$$ | $$w_3=\frac{\hat{w}_3}{\Arrowvert\hat{w}_3\Arrowvert}$$ |
| ...                                                          | ...                                                     |

### Esercitazione 2: Serie e Trasformata di Fourier

Espansione in **Serie di Fourier**:

$$
x(t)=\sum_{n = - \infty}^{\infty} \mu_n e^{j\frac{2\pi}{T}nt}
$$

**Coefficienti della serie**:

$$
\mu_n=\frac{1}{\sqrt{T}}c_n=\frac{1}{T} \int_{-T/2}^{T/2}x(t)e^{-j\frac{2\pi}{T}nt}
$$

L'**energia** di un segnale espanso in serie di Fourier può essere calcolata anche come:

$$
E(x)=T \sum_n |\mu_n|^2
$$

Inoltre è da notare che i coefficienti della serie di Fourier sono uguali ai coefficienti della trasformata di Fourier.

### Esercitazione 3-4-5: Sistemi lineari

#### Proprietà

- **Linearità**: Vale il principio di sovrapposizione degli effetti.

- **Tempo invarianza**: Un ritardo sugli ingressi corrisponde ad un ritardo sulle uscite.

  $$
  T[x(t)]=y(t) \Longleftrightarrow T[x(t-\theta)]=y(t-\theta)
  $$

- **Causalità**: L'uscita ad un tempo generico non dipende da uscite in istanti di tempo precedenti. Il sistema è senza memoria. Questo lo rende fisicamente realizzabile se è LTI.

  $$
  h(t)=0 \hspace{0.5cm} se \ t<0
  $$

- **Stabilità**: Se l'ingresso ha ampiezza limitata, anche l'uscita ha ampiezza limitata:

  $$
  \int_{-\infty}^{\infty}|h(t)|^2dt<\infty
  $$

#### Segnali ad energia finita

**Funzione di autocorrelazione** di un segnale ad energia finita:

$$
R_x(\tau)=\int_{-\infty}^{\infty}x(t+\tau)x^*(t) dt
$$

**Spettro di energia**:

$$
S_x(f)=F\{R_x(\tau)\}=|X(f)|^2
$$

**Funzione di mutua correlazione**:

$$
R_{xy}(\tau)=\int_{-\infty}^{\infty}x(t+\tau)y^*(t) dt
$$

La funzione di autocorrelazione, calcolata in 0, e l'integrale su tutto il dominio dello spettro, forniscono entrambi il valore dell'energia del segnale:

$$
R_x(0)=\int_{-\infty}^{\infty}x(t) \cdot x^*(t) dt  = E(x) = \int_{-\infty}^{\infty}S_x(f) df
$$

Una proprietà dei sistemi ad energia media finita è la seguente:

$$
S_y(f)=|H(f)|^2S_x(f)
$$

#### Segnali periodici

Per un segnale periodico, la potenza è finita, e si può calcolare come visto nell'esercitazione 1, oppure con la somma dei quadrati dei moduli dei coefficienti della trasformata di Fourier: $$P(x)=\sum_i \|\mu_i\|^2$$.

**Funzione di autocorrelazione** di un segnale periodico:

$$
R_x(\tau)=\frac{1}{T}\int_{-T/2}^{T/2}x(t+\tau)x^*(t) dt
$$

**Spettro di potenza**:

$$
G_x(f)=\sum_i |\mu_i|^2 \delta(f-\frac{i}{T})
$$

#### Segnali a potenza media finita

**Funzione di autocorrelazione** di un segnale a potenza finita:
$$
\Phi_x(\tau)=\lim_{T \rightarrow \infty}\frac{1}{T} \int_{-T/2}^{T/2}x(t+\tau)x^*(t) dt
$$

**Spettro di potenza**:

$$
G_x(f)=F\{\Phi_x(\tau)\}=\lim_{T \rightarrow \infty}\frac{1}{T}|X_T(f)|^2
$$

La funzione di autocorrelazione, calcolata in 0, e l'integrale su tutto il dominio dello spettro, forniscono entrambi il valore dell'energia del segnale:

$$
\Phi_x(0)=\lim_{T \rightarrow \infty}\frac{1}{T} \int_{-T/2}^{T/2}x(t) \cdot x^*(t) dt=P(x)= \int_{-\infty}^{\infty}G_x(f) df
$$

Una proprietà dei sistemi ad energia media finita è la seguente:

$$
G_y(f)=|H(f)|^2G_x(f)
$$

### Esercitazione 6: Processi casuali

Una variabile casuale assume dei valori che dipendono dal risultato di un esperimento casuale, il processo casuale è un'estensione nel mondo dei segnali. Si può interpretare come:

- l'insieme di funzioni del tempo per ciascun valore possibile della variabile casuale: $$x(t,s_0)$$.
- la collezione di valori dati dalla variabile casuale per ogni istante di tempo: $$x(t_0,s)$$.

**Valore atteso**:

$$
E[x(t)]=\int_{- \infty}^{+ \infty}x f_{\xi}(x,t)dx
$$

**Media temporale**:

$$
\langle x(t) \rangle = \lim_{T \rightarrow \infty} \frac{1}{T} \int_{- T/2}^{+ T/2} x(t)dt
$$

**Funzione di autocorrelazione**:

$$
R_x(t_1,t_2)=E[x(t_1)x(t_2)]=\int_{- \infty}^{+ \infty}x_1x_2f_{\xi_1\xi_2}(x_1,x_2;t_1,t_2)dx_1dx_2
$$

**Processi stazionari in senso stretto**: Un processo $$x(t) $$ si dice stazionario in senso stretto quando qualunque media statistica, calcolata su qualunque intervallo $$x(t) \ o \ x(t+\Delta t)$$ da' lo stesso risultato.

**Processi stazionari in senso lato**: Un processo si dice stazionario in senso lato se sono verificate le condizioni:

- Il valore atteso di $$E[x(t)]$$ è una costante che non dipende dal tempo.

- La funzione di autocorrelazione non dipende separatamente da 2 istanti di tempo, ma dalla loro differenza, $$\tau = t_1 - t_2 $$. Quindi si può riscrivere:

    $$
    R_x(\tau)=E[x(t)x^*(t+\tau)]
    $$

La funzione di autocorrelazione di un processo stazionario in senso lato è una funzione pari con un massimo in 0, pari al valor quadratico medio del processo $$R_x(0)=E[x^2(t)]$$. Se non ci sono componenti periodiche, inoltre, $$\lim_{\tau \rightarrow \infty} R_x(\tau)=(E[x(t)])^2$$.

**Trasformazioni lineari di processi casuali**: valgono alcune proprietà quando si mette un processo casuale all'ingresso di un sistema LTI.

- Se $$x(t) $$ è <u>stazionario</u>, anche $$y(t) $$ lo è.

- Si dimostra che il <u>valore atteso</u> in uscita è legato in questo modo al valore atteso dell'ingresso:

    $$
    E[y(t)]=E[x(t)]H(0)
    $$
    Se l'ingresso è a media nulla, anche l'uscita ha media nulla.

- Si dimostra che lo <u>spettro di potenza</u> in uscita è legato in questo modo al valore atteso dell'ingresso:

    $$
    G_y(f)=G_x(f)|H(f)|^2
    $$

- La <u>funzione di autocorrelazione</u> del processo $$y(t)$$ vale:

    $$
    R_y(\tau)= R_x(\tau) \circledast R_h(\tau)
    $$

- La <u>mutua correlazione ingresso-uscita</u> vale:

    $$
    R_{x,y}(\tau)= R_x(\tau) \circledast h(\tau)
    $$

**Ergodicità**: Quando una media statistica $$E[g[x(t)]]$$ di un processo stazionario $$x(t) $$ è uguale alla corrispondente media temporale calcolata su di una qualsiasi funzione campione, allora il processo si dice ergodico per quella media. Se il processo si dice ergodico per ogni media, allora si dice ergodico.

### Esercitazione 7: Campionamento

La **frequenza di Niequist** è pari al doppio della banda base di un segnale, è la frequenza <u>minima</u> di campionamento che permette la ricostruzione del segnale senza perdita di informazioni:

$$
f_N=2B_x
$$

L'operazione di campionamento di un segnale corrisponde ad una moltiplicazione per un treno di delta:

$$
x_c(t)=x(t)\cdot \sum_{n=-\infty}^{\infty} \delta(t-nT) = \sum_{n=-\infty}^{\infty} x(nT)\cdot \delta(t-nT)
$$

In questo caso, quindi, $$1/T$$ deve essere maggiore del doppio della banda di $$x(t)$$: $$\frac{1}{T}=f_c>2B_x$$. Per ricostruire il segnale si passa nel dominio della frequenza:

$$
X_c(f)=\frac{1}{T}\sum_{n}x(\frac{n}{T})\cdot \delta(f-\frac{n}{T})
$$

Poi bisogna trovare un filtro $$H(f)$$ che permetta di estrarre, dal segnale campionato, un campione singolo, in modo che:

$$
X_c(f) \cdot H(f) = X(f)
$$

E tornando nel dominio del tempo si ricostruisce il segnale iniziale senza alcuna perdita (se viene rispettato il campionamento con la frequenza minima di Niequist).

## Elaborazione dei segnali

### Esercitazione 1: Segnali a tempo discreto

**Causalità**: Una sequenza è detta <u>causale</u> se è nulla per valori di $$n \lt 0$$, <u>anticausale</u> se è nulla per valori di $$n \ge 0$$.

**Sequenze assolutamente sommabili**:

$$
\sum_{n=-\infty}^{\infty} |x(n)| \lt \infty
$$

 **Sequenze quadraticamente sommabili**:

$$
\sum_{n=-\infty}^{\infty} |x(n)|^2 \lt \infty
$$

**Convoluzione lineare**:

$$
q(n)=x(n) \circledast y(n) = \sum_{k=-\infty}^{\infty} x(k)y(n-k)
$$

**Energia di un segnale a tempo discreto**:

$$
E_x=\sum_n|x(n)|^2
$$

L'energia non dipende tra traslazioni temporali:

$$
\sum_n|x(n)|^2=\sum_n|x(n-N)|^2 \hspace{2cm} \forall N \ intero
$$

**Potenza media**, per sequenze ad energia infinita, è possibile definirla come:

$$
P_x=\lim_{N \rightarrow \infty} \frac{1}{2N+1} \sum_{n=-N}^{N}|x(n)|^2
$$

**Potenza media di sequenze periodiche**:

$$
P_x=\frac{1}{N} \sum_{n=0}^{N-1}|x(n)|^2
$$

**Funzione di mutua correlazione**:

$$
R_{x,y}(n)=\sum_{k= - \infty}^{+\infty} x(k)y^*(k+n) = R_{x,y}(-n)
$$

Esercitazione 2: DTFT

<u>DTFT (Discrete Time Fourier Transform)</u>: permette di trasformare una qualsiasi sequenza x(n) del tempo discreto in una funzione continua della variabile f reale.

$$
X(e^{j2 \pi f})= \sum_{k= - \infty}^{+ \infty} x(k)e^{-j2 \pi f k}
$$

**Proprietà della DFTF**:

| **Proprietà**         | $$x(n),y(n)$$                   | **DFTF** $$X(e^{j2 \pi f})$$                              |
| --------------------- | ------------------------------- | --------------------------------------------------------- |
| Linearità             | $$a_1 x(n) + a_2 y(n)$$         | $$a_1 \cdot X(e^{j2 \pi f}) + a_2 \cdot Y(e^{j2 \pi f})$$ |
| Ribaltamento          | $$x(-n)$$                       | $$X(e^{-j2 \pi f})$$                                      |
| Ritardo               | $$x(n-N)$$                      | $$X(e^{j2 \pi f})e^{-j2 \pi fN}$$                         |
| Modulazione           | $$e^{j2 \pi f_0 n} \cdot x(n)$$ | $$X(e^{j2 \pi (f-f_0)})$$                                 |
| Derivata in freqienza | $$n \cdot x(n)$$                | $$\frac{j}{2 \pi} \frac{dX(e^{j2 \pi f})}{df}$$           |
| Convoluzione          | $$x(n) \circledast y(n)$$       | $$X(e^{j2 \pi f}) \cdot Y(e^{j2 \pi f})$$                 |
| Prodotto              | $$x(n) \cdot y(n)$$             | $$X(e^{j2 \pi f}) \circledast Y(e^{j2 \pi f})$$           |

**Spettro di energia**, sempre positivo $$\forall f$$:

$$
S_x (f)= |X(e^{j2 \pi f})|^2
$$

**Relazione di Parseval**,  consente di valutare l’energia di un segnale $x(n)$ a partire dalla conoscenza della DTFT, "*l’energia di una sequenza corrisponde a quella della sua DTFT calcolata sul suo periodo.*":

$$
E_x= \sum_{k = -\infty}^{+\infty}|x(k)|^2 = \int_{-1/2}^{1/2}|X(e^{j2 \pi f})|^2df
$$

### Esercitazione 3-4: DFT

<u>DFT (Discrete Fourier Transform)</u>: trasformata di Fourier di una sequenza di lunghezza finita pari a N campioni:

$$
X(k)=\sum_{n=0}^{N-1}x(n)e^{-j 2\pi n \frac{k}{N}} \hspace{1cm} \forall k= 0,1,2,...,N-1
$$

$$X(k)$$ può essere interpretata come la DTFT $$X(e^{j2πf})$$ valutata nelle N  frequenze equi-spaziate $$f_k= \frac{k}{N}$$.

### Esercitazione 5-6: Sistemi LTI discreti

#### Classificazione

**Sistemi lineari**: Per cui vale la sovrapposizione degli effetti.

**Sistemi tempo invarianti, o stazionari**: Un ritardo all'ingresso implica lo stesso ritardo sull'uscita, cioè il sistema ha un comportamento che non cambia con il tempo.

**Sistemi causali**:  Sono i sistemi in cui la risposta corrente, $$y(n)$$, non dipende dai valori futuri dell’ingresso, cioè da termini del tipo $$x(n+n_0)$$, dove $$n_0$$ é una costante intera qualsiasi e strettamente positiva ($$n_0 > 0$$).

**Sistemi con e senza memoria**:  I sistemi senza memoria sono i sistemi per cui la risposta corrente, $$y(n)$$, dipende solo dal valore dell’ingresso nel medesimo istante di tempo n, e non da termini dell’ingresso negli istanti di tempo precedenti.

**Sistemi passivi**: Un sistema a tempo discreto é detto passivo se ad un ingresso $$x(n)$$ con energia finita $$E_x$$ risponde con un segnale $$y(n)$$ con energia $$Ey \le Ex < \infty $$. Cioè deve essere verificata la seguente condizione:

$$
\sum_{m=- \infty}^{+\infty} |y(n)|^2 \le \sum_{m=- \infty}^{+\infty} |x(n)|^2
$$

Se la relazione precedente vale con il segno di uguaglianza, allora il sistema é detto senza perdite in quanto conserva l’energia del segnale di ingresso.

#### Analisi di sistemi LTI tramite trasformata zeta

**Sistemi LTI FIR (Finite Impulse Response)**: Nella relazione ingresso-uscita **non deve** essere presente una struttura ricorsiva. Un filtro FIR è necessariamente stabile.

**Sistemi LTI IIR (Infinite Impulse Response)**: Nella relazione ingresso-uscita **deve** essere presente una struttura ricorsiva.

**Stabilità in senso BIBO**: Se l'ingresso è limitato lo deve essere anche l'uscita:

$$
\int_{-\infty}^{\infty}h(t)dt < \infty
$$

**Sistema realizzabile fisicamente**:  Un sistema si dice fisicamente realizzabile se possiede una risposta all’impulso $$h(n)$$ reale e causale, oppure se l’equazione alle differenze è causale e i coefficienti sono reali.

I coefficienti di $$H(z)$$ sono tutti reali se e solo se per ogni polo o zero è presente anche il rispettivo complesso coniugato.

$$
h(t)=0 \hspace{2cm} se \ t<0
$$

**Sistemi a fase minima**: Un sistema LTI si dice “a fase minima” se tutti i poli e tutti gli zeri della funzione di trasferimento sono collocati all’interno del cerchio di raggio unitario.

------

*Questo, e altri formulari, o cheatsheets, sono disponibili qui:* [bit.ly/vcasalino-cheatsheets](https://bit.ly/vcasalino-cheatsheets){:target="_blank"}.
