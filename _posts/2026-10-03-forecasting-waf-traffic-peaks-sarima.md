---
title: "Forecasting WAF Traffic Peaks: SARIMA, and Why It Isn't Enough"
description: "Can a seasonal ARIMA model running on WAF logs predict legitimate traffic peaks and attack peaks for a home banking platform around pension days, paydays and holidays? A backtest on synthetic data shows where SARIMA breaks, and proposes a calendar-aware regression with ARIMA errors plus a negative binomial model for attack traffic instead."
categories:
  - research
  - waf
---
> **TL;DR** — SARIMA is a good *first* idea for forecasting WAF traffic, but
> the peaks a bank cares about (pension day, payday, tax deadlines,
> holidays) don't repeat on a fixed lag, so SARIMA misses exactly the days you
> built it for. Put the calendar into the model as regressors and keep ARIMA
> only for the leftover noise. Model attack traffic separately, as counts, and
> split it into the part you can predict and the part you can only detect.

Most WAF configurations I come across during assessments are **static**: a
rate limit of N requests per minute per IP, an anomaly threshold someone set
in 2019, an autoscaling policy that reacts *after* CPU is already at 90%. But
traffic to a home banking platform is anything but static. In Italy, for
instance:

- **pensions** are credited around the first banking day of the month, and
  a lot of people log in that morning to check they arrived;
- **salaries** typically land around the 27th;
- **F24 tax payments** are due on the 16th;
- **December** stacks the *tredicesima* (the 13th monthly payment) on top of
  everything else, while bank holidays and August empty the platform.

Attackers know this calendar too. Account takeover and smishing campaigns
(*"your pension payment is on hold, click here"*) cluster around the days
when accounts are funded and victims *expect* a message from their bank.

So the pitch is: **if the WAF already sees every request, why not have it
forecast the next month of traffic**, and use that forecast to pre-scale,
set rate limits and alert thresholds that follow the calendar, and tell
"busy pension day" apart from "something is wrong"? The textbook tool for a
series with a weekly rhythm is a **seasonal ARIMA (SARIMA)** model.

I wanted to see whether SARIMA actually holds up for this, so I tried to
break it.

> **About the data:** I don't have (and couldn't publish) a bank's WAF logs,
> so everything below runs on **synthetic** data from a simulator built to
> have the calendar effects described above. The numbers show *mechanisms*,
> not real-world accuracy. The whole thing is one script,
> [`waf-forecast-sim.py`](/assets/files/waf-forecast-sim.py): replace its
> `simulate()` with an export of your own logs and the same backtest runs
> on real data.

## What a forecast buys you at the WAF

Before the statistics, here's why it's worth the effort. A traffic forecast
with a **prediction interval** (the range the model expects the real value
to fall in, at a stated probability) gives you:

1. **Capacity planning that runs ahead of demand.** Scale the origin and the
   WAF tier the night before the 1st of December instead of during it.
2. **Rate limits and thresholds that follow the calendar.** Instead of "alert
   above 3M requests/day", alert above *the upper bound of what we expected
   for today*. 4M requests is normal on pension day and suspicious on a
   Sunday in August, and a fixed threshold can't tell those apart.
3. **Proactive anti-fraud posture.** If you know the ATO wave comes with the
   pension, you can turn on step-up authentication, stricter bot challenges
   on `/login` and tighter velocity checks on new payees *before* it starts.
4. **Better anomaly detection.** The *residual* (observed minus expected) is
   a much cleaner signal than the raw count, because the calendar has already
   been subtracted out.
5. **Operations.** Change freezes, SOC staffing and on-call coverage on the
   days that matter.

All five depend on the forecast being right **on the peak days**. Being
accurate on an ordinary Wednesday is easy and not worth much.

## SARIMA in five minutes

ARIMA models a series as a combination of its own past values (the **AR**
part, order *p*), past forecast errors (the **MA** part, order *q*), after
**differencing** *d* times to remove trends. SARIMA adds the same three
ingredients at a **seasonal lag** *s*, so for daily traffic with a weekly
rhythm, *s = 7* and "this Monday" is explained partly by "last Monday":

```text
SARIMA(p,d,q)(P,D,Q)s

  φ(B) Φ(Bˢ) (1−B)ᵈ (1−Bˢ)ᴰ log(yₜ) = θ(B) Θ(Bˢ) εₜ

  B      backshift operator, B·yₜ = yₜ₋₁
  φ, θ   non-seasonal AR / MA polynomials
  Φ, Θ   seasonal AR / MA polynomials at lag s
```

I model `log(requests)` rather than raw requests because the effects are
multiplicative (pension day is "+40%", not "+800k"), and because the log
keeps the variance roughly constant as traffic grows.

On the simulated data, a grid search by AIC picks
**SARIMA(2,0,1)(0,1,1)₇**, i.e. weekly seasonal differencing plus a
seasonal MA term. For a weekly series that's a perfectly reasonable textbook
model.

## The (synthetic) home banking platform

Three years of daily traffic, 2023–2025, built from:

| Component | Effect on daily traffic |
|---|---|
| Base level + growth | ~2M requests/day, +8%/year |
| Day of week | Monday +13%, Saturday −22%, Sunday −30% |
| Bank holidays (Italian calendar, Easter included) | −26% |
| August dip, December bump | −14% mid-August, +6% mid-December |
| Pension day (1st banking day) | +5% the day before, **+42%** on the day, +20% / +8% the two days after |
| December pension (*tredicesima*) | an extra **+16%** on top of the above |
| Payday (27th, or the banking day before) | +4%, **+25%**, +13%, +5% |
| F24 tax deadline (16th, or next banking day) | +5% the day before, +11% on the day |
| Noise | AR(1), ~4% daily |

![Synthetic legitimate requests per day, September to December 2025: a weekly sawtooth with sharp spikes on pension days and smaller ones on paydays, the largest on December 1st](/assets/img/waf-forecast-traffic.svg)

The weekly sawtooth is SARIMA's home turf. The spikes are the problem.

## Where SARIMA breaks

### 1. A month is not a season

SARIMA has *one* seasonal lag *s*, and it has to be a fixed number of
observations. Weekly is fine: a week is always 7 days. But pension day is
"the first banking day of the month", which in 2025 falls on:

```text
Thu 02 Jan · Mon 03 Feb · Mon 03 Mar · Tue 01 Apr · Fri 02 May · Tue 03 Jun
Tue 01 Jul · Fri 01 Aug · Mon 01 Sep · Wed 01 Oct · Mon 03 Nov · Mon 01 Dec

gaps (days): 32 28 29 31 32 28 31 31 30 33 28
```

There's no `s` that lines those up. Set `s = 30` and "the same day last
month" lands on the previous pension day exactly once in 2025 (1 September →
1 October). Every other month it's one to three days off, which is the
difference between the peak and an ordinary day. The payday (27th, moved
back to Friday when it falls on a weekend) and the F24 deadline (16th, moved
forward) have the same problem, in opposite directions. Easter changes date
every year. To SARIMA, all of these look like **noise**.

### 2. Seasonal differencing copies shocks forward

`(1 − B⁷)` means "model the change from last week". This works well on
ordinary weeks, but when the model is fed real data day by day, a one-off
event becomes part of the "last week" that next week is forecast from. The
seasonal MA term is supposed to absorb this, but it can only partly cancel a
spike it has no explanation for. The attack-traffic section below shows the
result: SARIMA's alert threshold jumps *the day after* a burst, exactly when
you'd want it to be strict.

### 3. Holidays look like random dips

8 December, Christmas and Easter Monday get forecast as ordinary weekdays,
because nothing in the model says they're holidays.

### The backtest

Every month from July to December 2025, each model is fit on all data up to
the last day of the previous month and forecasts the **whole next month**
(up to 31 days ahead, which is the horizon that matters for capacity
planning). The **seasonal naive** baseline just repeats the last observed
week. Any model has to beat it to be worth running.

| Model | MAPE, all days | MAPE, pension & paydays | Month's peak on the right day | Top-5 days identified | 95% interval coverage |
|---|---|---|---|---|---|
| Seasonal naive | 12.3% | 21.2% | 2 / 6 | 20% | n/a |
| **SARIMA(2,0,1)(0,1,1)₇** | 8.5% | **24.5%** | 3 / 6 | 47% | 90% |
| Regression + ARIMA errors (below) | **4.2%** | **3.5%** | **6 / 6** | **87%** | 90% |

*MAPE = mean absolute percentage error. "Top-5 days identified" = overlap
between each month's five busiest forecast days and its five busiest actual
days.*

SARIMA beats the naive baseline overall, but on the event days it's **worse
than the naive baseline**, and those are the days the forecast was built for.
December shows why:

![December 2025 forecast versus actual traffic: the actual series spikes to 4.8M on December 1st (pension plus tredicesima); SARIMA forecasts about 3.1M, while the calendar-aware regression forecasts about 5.0M and tracks the payday and holidays as well](/assets/img/waf-forecast-december.svg)

On 1 December (pension + *tredicesima*) SARIMA forecasts 3.1M requests
against 4.8M actual, a **36% underestimate** on the busiest day of the year
(the calendar-aware model below says 5.0M).
It also forecasts a normal Monday on the 8th (a bank holiday), a normal
Wednesday on the 24th (payday), and normal weekdays over Christmas.

## A better model: put the calendar *in* the model

The fix is not a cleverer ARIMA. It's to stop asking ARIMA to *discover*
the calendar and **tell it the calendar instead**. This is a **regression with
ARIMA errors** (also called dynamic regression, or SARIMAX with exogenous
regressors):

```text
log(yₜ) = β₀ + β₁·t                                  trend
        + Σ γ_d · DOWₜ,d                              day of week
        + Σ [aₖ sin(2πk·doyₜ/365.25) + bₖ cos(...)]   yearly shape, k = 1..4
        + δ_H · holidayₜ
        + Σ_{j=−1..2} δ_P,j · pensionₜ₋ⱼ              pension window
        + δ_D · (pensionₜ × Decemberₜ)                tredicesima
        + Σ_{j=−1..2} δ_S,j · paydayₜ₋ⱼ               payday window
        + Σ_{j=−1..0} δ_F,j · f24ₜ₋ⱼ                  tax deadline window
        + uₜ

uₜ ~ ARMA(1,1)                                         whatever is left
```

What changes:

- **Event windows, not event days.** Each event is a set of dummies for
  *j* days before and after it, so the model learns the shape (anticipation,
  peak, decay) rather than a single spike.
- **Events are computed from rules, not from lags.** "First banking day of
  the month" is a function of the calendar, so it's right whether the month
  has 28 or 31 days.
- **Yearly seasonality as Fourier terms**, not a 365-lag SARIMA (which would
  be numerically painful and would need several years of data per
  coefficient).
- **ARIMA is demoted to modeling the residual**, the short-term autocorrelation
  the calendar doesn't explain. That's what it's good at.

In `statsmodels` it's the same `SARIMAX` class, with an `exog` matrix:

```python
from statsmodels.tsa.statespace.sarimax import SARIMAX

X = design(calendar)          # const, trend, DOW, Fourier, event windows
model = SARIMAX(np.log(y[train]), exog=X[train], order=(1, 0, 1))
fit = model.fit(disp=False)

# the future calendar is known in advance, so exog for the horizon is too
fc = fit.get_forecast(steps=31, exog=X[next_month])
upper = np.exp(fc.conf_int(alpha=0.05).iloc[:, 1])
```

One gotcha: put the constant **in `exog`**, not in `trend="c"`. With the
intercept inside the ARMA part, the AR coefficient drifted to 0.996 and
absorbed the level, and the forecasts were off by 40%.

The other advantage is that the coefficients mean something. Fit on data up
to November 2025, the model recovers the simulated effects:

| Effect | Simulated | Estimated |
|---|---|---|
| Pension day | +42% | +42% (`e^0.352`) |
| Day after pension | +20% | +20% |
| December extra | +16% | +17% |
| Payday | +25% | +23% |
| F24 deadline | +11% | +11% |
| Bank holiday | −26% | −27% |

On real data, that table is something you can hand to the capacity planning
and fraud teams as is: *"pension day is +42%, and in December it's +66%."*

**Calibrate the interval before you alert on it.** Both models cover the
actual value 90% of the time with a nominal 95% interval. Month-ahead
forecast intervals in `statsmodels` don't account for uncertainty in the
estimated parameters, so they come out too narrow. Before an upper bound
becomes a rate limit or an alert threshold, check its coverage on a backtest
and widen it until it matches the nominal rate (a split-conformal correction
on recent residuals is the cheapest way to do that).

### What about hourly data?

Rate limits and autoscaling usually work at minute or hour resolution. With
hourly data you have *two* seasonal periods, 24 and 168, and SARIMA can only
handle one of them, and `s = 168` is slow and unstable to fit. The same
recipe still works: **Fourier terms for both the daily and the weekly cycle**
plus the calendar regressors and ARMA errors. Alternatively, forecast at
daily resolution with the model above and spread each day over hours using
an intraday profile learned separately for each type of day (weekday,
weekend, pension day). [MSTL](https://www.statsmodels.org/stable/examples/notebooks/generated/mstl_decomposition.html),
TBATS and Prophet (which has the holiday-window idea built in) are reasonable
alternatives if you'd rather not hand-roll it.

## Attack traffic is a different animal

Now the more interesting half: **can we predict attack peaks?** Some of
them. Treating blocked requests as one series and running SARIMA on it
misses the point, because WAF-blocked traffic is (at least) three processes
with very different behavior added together:

| Component | Driver | Predictable? |
|---|---|---|
| Background scanning | Internet noise, constant-ish, ignores your calendar | Yes: it's a slowly drifting level |
| Calendar-timed fraud (credential stuffing, ATO, smishing follow-ups) | Pension day, payday, *tredicesima* | **Yes**: same calendar as the users |
| Campaigns and DDoS bursts | An adversary choosing when to strike, often reacting to the news or to your defenses | **No**: only the *risk* is forecastable, not the date |

So the realistic goal is: **forecast the predictable part, and detect the
unpredictable part against it.**

The counts also aren't log-normal: they're **overdispersed counts** (the
variance is much larger than the mean, more than a Poisson distribution
allows), and bursts tend to come back the next day. A model that fits that
shape is a **negative binomial regression** with the same calendar
regressors plus a lag term for that self-excitation (a cheap stand-in for an
INGARCH/Hawkes process):

```text
blockedₜ ~ NegBin(μₜ, α)

log(μₜ) = β₀ + β₁·t + Σ δ · calendarₜ + ρ · log(1 + blockedₜ₋₁)
```

The alert threshold is the 99.5% quantile of that distribution, computed one
day ahead. Two details made a real difference:

- **Robust refit.** Past campaigns inflate the estimated dispersion α, which
  widens the threshold and hides the next campaign. Fit once, drop the
  in-sample days that exceed the threshold, refit.
- **The pension wave is *expected*, so it isn't an alert.** The threshold
  rises on pension days because the model knows the ATO wave is coming.
  That's not a blind spot: the same coefficient (+55% blocked traffic on
  pension day, another +51% in December) is what you use to tighten
  `/login` controls *in advance*.

One-day-ahead over all of 2025, against 11 injected campaigns:

| Model | Campaigns caught on day 1 | False alerts | …of which on pension/paydays | MAPE on pension & paydays |
|---|---|---|---|---|
| SARIMA on log(blocked) | 9 / 11 | 1 | 1 | 22.4% |
| **NB regression + calendar + lag** | **10 / 11** | 1 | **0** | **15.7%** |

The difference here is smaller than for legitimate traffic, and I don't
want to oversell it: for one-step-ahead detection SARIMA holds up reasonably
well. The difference is in **the shape of the threshold**:

![Blocked requests per day from May to August 2025 with one-day-ahead 99.5% alert thresholds: the NB threshold sits close above normal traffic and rises on pension days, while the SARIMA threshold sits about 28% higher and jumps up the day after every campaign spike](/assets/img/waf-forecast-attacks.svg)

- The SARIMA threshold sits **~28% higher** on a typical day, so smaller
  campaigns pass under it (the 13 June one at ~98k is caught by the NB model
  and missed by SARIMA).
- It **jumps the day after every burst**: the attack becomes part of "last
  week", so a second wave that arrives while the threshold is up goes
  unnoticed.
- The NB threshold rises **only where the calendar says it should**: the
  small blue bumps on 3 June, 1 July and 1 August are pension days.

## Putting it in production

<div class="mermaid">
graph LR
  A[WAF logs] --> B[Aggregate per app & endpoint<br/>allowed vs blocked]
  C[Calendar rules<br/>holidays, pension, payday, F24] --> D
  B --> D[Nightly refit<br/>legit: regression + ARMA<br/>attack: NB + calendar + lag]
  D --> E[Forecast + calibrated bounds<br/>next 31 days]
  E --> F[Autoscaling schedule]
  E --> G[Dynamic rate limits<br/>& step-up auth on peak days]
  E --> H[SIEM: alert on residual<br/>above upper bound]
</div>

Things I'd watch out for:

- **Model per endpoint, not per site.** `/login`, `/payments` and static
  assets have different peaks and different attackers. A site-wide
  aggregate hides an ATO wave under the morning rush.
- **Keep the training data clean.** The legitimate-traffic model should be
  trained on traffic that was allowed *and* not flagged later by fraud
  detection. Otherwise every attack you missed becomes part of "normal".
- **Baseline poisoning is a real attack.** An adversary who ramps up slowly
  can drag an adaptive baseline up with them (the "boiling frog"). Cap how
  fast the level and trend may move between refits, keep a frozen reference
  model to compare against, and have a human review big coefficient changes.
- **The calendar is now code, and it needs maintenance.** Payment schedules
  change (during COVID, pension payouts at Italian post offices were
  staggered over several days),
  new holidays appear, and marketing campaigns or app releases are events
  too. Whoever owns the calendar table owns forecast accuracy.
- **Watch interval coverage, not just error.** If the 99.5% bound starts
  getting exceeded 3% of the time, either attacks are up or the model is
  stale, and both need someone to look.

## The model I'd actually propose

To sum up the challenge to plain SARIMA:

| | Plain SARIMA | Proposed |
|---|---|---|
| Weekly cycle | Seasonal lag 7 | Day-of-week dummies (or Fourier terms at hourly resolution) |
| Monthly events | Can't represent them: no fixed lag | Rule-based event windows with lead/lag dummies |
| Holidays, Easter | Seen as noise | Holiday regressor from a maintained calendar |
| Yearly shape | Not modeled (or a 365-lag SARIMA) | Fourier terms |
| Short-term noise | Everything | ARMA(1,1) on the residual only |
| Attack traffic | Same model on log counts | Separate NB count model: calendar + self-exciting lag + robust refit |
| Thresholds | Model interval, as is | Interval calibrated on backtests (conformal) |
| Interpretability | Opaque coefficients | "Pension day = +42%" |

None of this is exotic: it's still `SARIMAX` from `statsmodels`, still fits
in seconds, and still explainable to an auditor. The only change is that the
model is told about the calendar instead of having to discover it.

If you run the [script](/assets/files/waf-forecast-sim.py) against real WAF
exports, I'd love to hear how far the real numbers are from the synthetic
ones, especially for the attack side, where I'd expect real campaigns to be
much less polite than my lognormal bursts. 🙂
