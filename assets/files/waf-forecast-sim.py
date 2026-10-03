#!/usr/bin/env python3
"""
Companion script for the blog post "Forecasting WAF Traffic Peaks: SARIMA,
and Why It Isn't Enough".

Simulates three years of daily traffic for a fictional Italian home banking
platform (legitimate requests + WAF-blocked attack requests), then compares:

  legitimate traffic  -> seasonal naive vs SARIMA vs regression with ARIMA
                         errors (calendar regressors + Fourier terms)
  attack traffic      -> SARIMA vs negative binomial regression with calendar
                         regressors and a self-exciting lag term

All data is synthetic: the numbers show *mechanisms*, not real-world
performance. Swap `simulate()` for your own WAF logs to get real ones.

    pip install numpy pandas scipy statsmodels matplotlib
    python3 waf-forecast-sim.py            # prints metrics
    python3 waf-forecast-sim.py --plots    # also writes the SVG figures
"""
import sys
import warnings
from datetime import date, timedelta

import numpy as np
import pandas as pd
import statsmodels.api as sm
from scipy import stats
from statsmodels.tsa.statespace.sarimax import SARIMAX

warnings.filterwarnings("ignore")
rng = np.random.default_rng(42)

START, END = "2023-01-01", "2025-12-31"
TEST_MONTHS = pd.period_range("2025-07", "2025-12", freq="M")
ATTACK_MONTHS = pd.period_range("2025-01", "2025-12", freq="M")


# --------------------------------------------------------------------------
# Italian banking calendar
# --------------------------------------------------------------------------
def easter(y):
    a, b, c = y % 19, y // 100, y % 100
    d, e = b // 4, b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = ((h + l - 7 * m + 114) % 31) + 1
    return date(y, month, day)


def holidays(years):
    out = set()
    for y in years:
        for m, d in [(1, 1), (1, 6), (4, 25), (5, 1), (6, 2), (8, 15),
                     (11, 1), (12, 8), (12, 25), (12, 26)]:
            out.add(date(y, m, d))
        out.add(easter(y) + timedelta(days=1))  # Pasquetta
    return out


def calendar(idx):
    hol = holidays(range(idx[0].year, idx[-1].year + 1))
    days = [d.date() for d in idx]
    is_hol = np.array([d in hol for d in days])
    is_bday = (idx.dayofweek < 5) & ~is_hol

    bdays = set(np.array(days)[is_bday])

    def next_bday(d):
        while d not in bdays:
            d += timedelta(days=1)
        return d

    def prev_bday(d):
        while d not in bdays:
            d -= timedelta(days=1)
        return d

    pension, payday, tax = set(), set(), set()
    for p in pd.period_range(idx[0], idx[-1], freq="M"):
        y, m = p.year, p.month
        pension.add(next_bday(date(y, m, 1)))  # INPS: 1st banking day
        payday.add(prev_bday(date(y, m, 27)))  # common private payroll date
        tax.add(next_bday(date(y, m, 16)))     # F24 payment deadline

    def window(events, lags):
        """One column per offset: 1 if `d - offset` is an event day."""
        cols = {}
        for k in lags:
            cols[k] = np.array([(d - timedelta(days=k)) in events for d in days])
        return cols

    cal = pd.DataFrame(index=idx)
    cal["dow"] = idx.dayofweek
    cal["holiday"] = is_hol.astype(float)
    for k, v in window(pension, [-1, 0, 1, 2]).items():
        cal[f"pension{k:+d}"] = v.astype(float)
    for k, v in window(payday, [-1, 0, 1, 2]).items():
        cal[f"payday{k:+d}"] = v.astype(float)
    for k, v in window(tax, [-1, 0]).items():
        cal[f"tax{k:+d}"] = v.astype(float)
    # December pension carries the tredicesima (13th monthly payment)
    cal["dec_pension"] = cal["pension+0"] * (idx.month == 12)
    return cal


# --------------------------------------------------------------------------
# Synthetic traffic
# --------------------------------------------------------------------------
def simulate():
    idx = pd.date_range(START, END, freq="D")
    cal = calendar(idx)
    n = len(idx)
    t = np.arange(n)
    doy = idx.dayofyear.values

    dow_eff = np.array([0.12, 0.06, 0.03, 0.02, 0.0, -0.25, -0.35])
    log_legit = (
        np.log(2.0e6)
        + 0.08 * t / 365.25                                       # growth
        + dow_eff[cal["dow"].values]
        - 0.30 * cal["holiday"]
        - 0.15 * np.exp(-0.5 * ((doy - 227) / 9) ** 2)           # August
        + 0.06 * np.exp(-0.5 * ((doy - 350) / 12) ** 2)          # December
        + 0.05 * cal["pension-1"] + 0.35 * cal["pension+0"]
        + 0.18 * cal["pension+1"] + 0.08 * cal["pension+2"]
        + 0.15 * cal["dec_pension"]
        + 0.04 * cal["payday-1"] + 0.22 * cal["payday+0"]
        + 0.12 * cal["payday+1"] + 0.05 * cal["payday+2"]
        + 0.05 * cal["tax-1"] + 0.10 * cal["tax+0"]
    ).values
    ar = np.zeros(n)
    for i in range(1, n):
        ar[i] = 0.5 * ar[i - 1] + rng.normal(0, 0.035)
    legit = np.exp(log_legit + ar)

    # attack traffic = scanners + calendar-timed ATO/fraud + bursty campaigns
    scan = 4.0e4 * np.exp(0.05 * t / 365.25)
    ato = 1.5e4 * np.exp(
        1.10 * cal["pension+0"] + 0.70 * cal["pension+1"]
        + 0.35 * cal["pension-1"] + 0.60 * cal["payday+0"]
        + 0.30 * cal["payday+1"] + 0.40 * cal["dec_pension"]
    ).values
    campaign = np.zeros(n)
    labels = np.zeros(n, dtype=int)             # campaign id, 0 = none
    cid = 0
    for i in range(n):
        if rng.random() < 0.025:                # a campaign starts
            cid += 1
            size = rng.lognormal(np.log(1.2e5), 0.6)
            for k in range(rng.integers(1, 4)):  # lasts 1-3 days, decaying
                if i + k < n:
                    campaign[i + k] += size * 0.55 ** k
                    labels[i + k] = cid
    mu = scan + ato + campaign
    alpha = 0.03                                # NB overdispersion
    attack = rng.negative_binomial(1 / alpha, 1 / (1 + alpha * mu))

    df = pd.DataFrame({"legit": legit, "attack": attack.astype(float),
                       "campaign": labels}, index=idx)
    return df, cal


# --------------------------------------------------------------------------
# Legitimate traffic models
# --------------------------------------------------------------------------
EVENT_COLS = ["holiday", "pension-1", "pension+0", "pension+1", "pension+2",
              "dec_pension", "payday-1", "payday+0", "payday+1", "payday+2",
              "tax-1", "tax+0"]


def design(cal, t0):
    """Exogenous regressors for the proposed model."""
    idx = cal.index
    X = pd.get_dummies(cal["dow"], prefix="dow", drop_first=True).astype(float)
    X.index = idx
    X.insert(0, "const", 1.0)
    X["trend"] = (idx - pd.Timestamp(t0)).days / 365.25
    doy = idx.dayofyear.values
    for k in (1, 2, 3, 4):  # yearly seasonality as Fourier pairs
        X[f"sin{k}"] = np.sin(2 * np.pi * k * doy / 365.25)
        X[f"cos{k}"] = np.cos(2 * np.pi * k * doy / 365.25)
    return pd.concat([X, cal[EVENT_COLS]], axis=1)


def pick_sarima(y):
    best = None
    for p in (0, 1, 2):
        for q in (0, 1, 2):
            for P in (0, 1):
                for Q in (0, 1):
                    for d in (0, 1):
                        try:
                            r = SARIMAX(y, order=(p, d, q),
                                        seasonal_order=(P, 1, Q, 7)
                                        ).fit(disp=False)
                        except Exception:
                            continue
                        if best is None or r.aic < best[0]:
                            best = (r.aic, (p, d, q), (P, 1, Q, 7))
    return best[1], best[2]


def legit_backtest(df, cal):
    y = np.log(df["legit"])
    X = design(cal, START)
    first = TEST_MONTHS[0].start_time
    order, sorder = pick_sarima(y[y.index < first])
    print(f"SARIMA picked by AIC: {order}x{sorder}")

    rows = []
    for m in TEST_MONTHS:
        train = y.index < m.start_time
        test = (y.index >= m.start_time) & (y.index <= m.end_time)
        h = int(test.sum())

        s = SARIMAX(y[train], order=order, seasonal_order=sorder
                    ).fit(disp=False).get_forecast(h)
        s_ci = s.conf_int(alpha=0.05).values

        # constant lives in exog, so this is y = X*beta + ARMA(1,1) noise
        r = SARIMAX(y[train], exog=X[train], order=(1, 0, 1)
                    ).fit(disp=False, maxiter=200)
        r_fc = r.get_forecast(h, exog=X[test])
        r_ci = r_fc.conf_int(alpha=0.05).values

        # seasonal naive: same weekday, last week of training repeated
        last_week = y[train].values[-7:]
        snaive = np.resize(last_week, h)

        for i, d in enumerate(y.index[test]):
            rows.append({
                "date": d, "actual": df["legit"][d],
                "snaive": np.exp(snaive[i]),
                "sarima": np.exp(s.predicted_mean.values[i]),
                "sarima_lo": np.exp(s_ci[i, 0]), "sarima_hi": np.exp(s_ci[i, 1]),
                "prop": np.exp(r_fc.predicted_mean.values[i]),
                "prop_lo": np.exp(r_ci[i, 0]), "prop_hi": np.exp(r_ci[i, 1]),
            })
    out = pd.DataFrame(rows).set_index("date")
    out["event"] = (cal.loc[out.index, ["pension+0", "payday+0"]].sum(axis=1) > 0)
    return out, order, sorder, r


def legit_metrics(bt):
    def mape(col, mask=slice(None)):
        a, f = bt["actual"][mask], bt[col][mask]
        return float(np.mean(np.abs(f - a) / a) * 100)

    res = {}
    for col in ("snaive", "sarima", "prop"):
        res[col] = {"mape_all": mape(col), "mape_event": mape(col, bt["event"])}
        # did the model put the month's peak on the right day?
        hit = 0
        for _, g in bt.groupby(bt.index.to_period("M")):
            hit += g["actual"].idxmax() == g[col].idxmax()
        res[col]["peak_hits"] = f"{hit}/{len(TEST_MONTHS)}"
        # do the forecast top-5 days of each month match the actual top-5?
        ov = []
        for _, g in bt.groupby(bt.index.to_period("M")):
            ov.append(len(set(g["actual"].nlargest(5).index)
                          & set(g[col].nlargest(5).index)) / 5)
        res[col]["top5_overlap"] = float(np.mean(ov) * 100)
    for col in ("sarima", "prop"):
        a = bt["actual"]
        res[col]["cov95"] = float(((a >= bt[f"{col}_lo"]) &
                                   (a <= bt[f"{col}_hi"])).mean() * 100)
    return res


# --------------------------------------------------------------------------
# Attack traffic models (one-step-ahead, rolling)
# --------------------------------------------------------------------------
ATTACK_COLS = ["pension-1", "pension+0", "pension+1", "payday+0", "payday+1",
               "dec_pension"]


def attack_backtest(df, cal):
    y = df["attack"]
    first = TEST_MONTHS[0].start_time
    q = 0.995

    X = cal[ATTACK_COLS].copy()
    X["lag1"] = np.log1p(y.shift(1))
    X["trend"] = (y.index - pd.Timestamp(START)).days / 365.25
    X = sm.add_constant(X)

    rows = []
    for m in ATTACK_MONTHS:
        train = (y.index < m.start_time) & X["lag1"].notna()
        test = (y.index >= m.start_time) & (y.index <= m.end_time)

        nb = sm.NegativeBinomial(y[train], X[train]).fit(disp=False, maxiter=500)
        # robust refit: past bursts inflate the dispersion estimate (and so
        # the alert threshold), so drop in-sample exceedances and refit once
        a0 = nb.params["alpha"]
        mu0 = nb.predict(X[train])
        keep = y[train] <= stats.nbinom.ppf(q, 1 / a0, 1 / (1 + a0 * mu0))
        nb = sm.NegativeBinomial(y[train][keep], X[train][keep]
                                 ).fit(disp=False, maxiter=500)
        alpha = nb.params["alpha"]
        mu = nb.predict(X[test])  # uses the *observed* lag1: one-step-ahead
        nb_hi = stats.nbinom.ppf(q, 1 / alpha, 1 / (1 + alpha * mu))

        # SARIMA on log counts, refit each month, one-step-ahead via filtering
        ly = np.log(y)
        s = SARIMAX(ly[y.index < m.start_time], order=(1, 0, 1),
                    seasonal_order=(1, 1, 1, 7)).fit(disp=False)
        s_all = s.apply(ly[y.index <= m.end_time])
        pr = s_all.get_prediction(start=m.start_time, end=m.end_time)
        s_mu = np.exp(pr.predicted_mean.values)
        s_hi = np.exp(pr.conf_int(alpha=2 * (1 - q)).values[:, 1])

        for i, d in enumerate(y.index[test]):
            rows.append({"date": d, "actual": y[d], "campaign": df["campaign"][d],
                         "nb_mu": mu.iloc[i], "nb_hi": nb_hi[i],
                         "sarima_mu": s_mu[i], "sarima_hi": s_hi[i]})
    out = pd.DataFrame(rows).set_index("date")
    out["calendar_peak"] = (cal.loc[out.index, ["pension+0", "payday+0"]]
                            .sum(axis=1) > 0)
    return out, nb


def attack_metrics(at):
    res = {}
    clean = at["campaign"] == 0
    # a campaign counts as caught if its first day raises an alert
    onset = (at["campaign"] > 0) & (at["campaign"] != at["campaign"].shift(1))
    for m in ("sarima", "nb"):
        alert = at["actual"] > at[f"{m}_hi"]
        res[m] = {
            "campaigns_caught_day1": f"{int((alert & onset).sum())}"
                                     f"/{int(onset.sum())}",
            "false_alerts": int((alert & clean).sum()),
            "false_alerts_on_calendar_peaks":
                int((alert & clean & at["calendar_peak"]).sum()),
            "mape_calendar_peaks": float(
                (np.abs(at[f"{m}_mu"] - at["actual"]) / at["actual"])
                [clean & at["calendar_peak"]].mean() * 100),
            "mape_clean_days": float(
                (np.abs(at[f"{m}_mu"] - at["actual"]) / at["actual"])
                [clean].mean() * 100),
        }
    return res


# --------------------------------------------------------------------------
# Figures (SVG, light/dark aware via prefers-color-scheme)
# --------------------------------------------------------------------------
LIGHT = {"surface": "#fbfaf7", "ink": "#1c1c1c", "muted": "#6b6b6b",
         "grid": "#e2ded4", "s1": "#2a78d6", "s2": "#eb6834"}
DARK = {"surface": "#14161a", "ink": "#e7e6e2", "muted": "#9aa0a6",
        "grid": "#2a2e35", "s1": "#3987e5", "s2": "#d95926"}
# unlikely placeholder colors matplotlib draws with, rewritten to CSS vars
PH = {"surface": "#010101", "ink": "#020202", "muted": "#030303",
      "grid": "#040404", "s1": "#050505", "s2": "#060606"}


def themed_svg(fig, path):
    import io
    buf = io.StringIO()
    fig.savefig(buf, format="svg", facecolor=PH["surface"],
                metadata={"Date": None})
    svg = buf.getvalue()
    for k, v in PH.items():
        svg = svg.replace(v, f"var(--{k})")
    css = (
        "<style>svg{" + "".join(f"--{k}:{v};" for k, v in LIGHT.items()) + "}"
        "@media (prefers-color-scheme: dark){svg{"
        + "".join(f"--{k}:{v};" for k, v in DARK.items()) + "}}"
        "text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace!important}"
        "</style>"
    )
    svg = svg.replace("<defs>", css + "<defs>", 1)
    with open(path, "w") as f:
        f.write(svg)


def setup_mpl():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "svg.fonttype": "none", "font.size": 9,
        "font.family": "monospace",
        "axes.edgecolor": PH["grid"], "axes.labelcolor": PH["muted"],
        "xtick.color": PH["muted"], "ytick.color": PH["muted"],
        "text.color": PH["ink"], "axes.facecolor": PH["surface"],
        "axes.grid": True, "grid.color": PH["grid"], "grid.linewidth": 0.6,
        "axes.spines.top": False, "axes.spines.right": False,
        "legend.frameon": False, "svg.hashsalt": "waf",
    })
    return plt


def fmt_m(ax):
    from matplotlib.ticker import FuncFormatter
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1e6:.1f}M"))


def fmt_k(ax):
    from matplotlib.ticker import FuncFormatter
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1e3:.0f}k"))


def plots(df, cal, bt, at, outdir):
    plt = setup_mpl()
    import matplotlib.dates as mdates

    # 1. the raw series: weekly rhythm + calendar spikes
    w = df.loc["2025-09-01":"2025-12-31"]
    c = cal.loc[w.index]
    fig, ax = plt.subplots(figsize=(7.2, 3.0))
    ax.plot(w.index, w["legit"], color=PH["ink"], lw=1.4)
    for col, lab, mk in (("pension+0", "pension day", "o"),
                         ("payday+0", "payday (27th)", "s")):
        d = w.index[c[col] > 0]
        ax.plot(d, w["legit"][d], mk, ms=6, color=PH["s1" if mk == "o" else "s2"],
                mec=PH["surface"], mew=1.5, label=lab, ls="none")
    ax.set_title("Legitimate requests/day, synthetic home banking",
                 loc="left", fontsize=10, color=PH["ink"])
    fmt_m(ax)
    ax.xaxis.set_major_locator(mdates.MonthLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    ax.legend(loc="upper left", ncol=2)
    fig.tight_layout()
    themed_svg(fig, f"{outdir}/waf-forecast-traffic.svg")

    # 2. one month of forecasts: SARIMA vs proposed
    m = bt.loc["2025-12-01":"2025-12-31"]
    fig, ax = plt.subplots(figsize=(7.2, 3.2))
    ax.fill_between(m.index, m["prop_lo"], m["prop_hi"], color=PH["s1"],
                    alpha=0.15, lw=0)
    ax.plot(m.index, m["actual"], color=PH["ink"], lw=1.6, label="actual")
    ax.plot(m.index, m["sarima"], color=PH["s2"], lw=1.6, ls="--",
            label="SARIMA")
    ax.plot(m.index, m["prop"], color=PH["s1"], lw=1.6,
            label="regression + ARIMA errors (95% band)")
    ax.set_title("December 2025, forecast made on Nov 30 (31 days ahead)",
                 loc="left", fontsize=10, color=PH["ink"])
    fmt_m(ax)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d"))
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    themed_svg(fig, f"{outdir}/waf-forecast-december.svg")

    # 3. attack traffic, one-step-ahead thresholds
    a = at.loc["2025-05-01":"2025-08-31"]
    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    ax.plot(a.index, a["actual"], color=PH["ink"], lw=1.2,
            label="blocked requests")
    ax.plot(a.index, a["nb_hi"], color=PH["s1"], lw=1.4,
            label="NB alert threshold")
    ax.plot(a.index, a["sarima_hi"], color=PH["s2"], lw=1.4, ls="--",
            label="SARIMA alert threshold")
    onset = (a["campaign"] > 0) & (a["campaign"] != a["campaign"].shift(1))
    ax.plot(a.index[onset], a["actual"][onset], "v", ms=7, color=PH["ink"],
            mfc=PH["surface"], mew=1.4, ls="none", label="campaign starts")
    ax.set_title("WAF-blocked requests/day vs one-day-ahead 99.5% thresholds",
                 loc="left", fontsize=10, color=PH["ink"], pad=38)
    fmt_k(ax)
    ax.set_ylim(0, a["actual"].max() * 1.08)
    ax.xaxis.set_major_locator(mdates.MonthLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), fontsize=8, ncol=2,
              handlelength=1.8, columnspacing=1.2, borderaxespad=0.2)
    fig.tight_layout()
    themed_svg(fig, f"{outdir}/waf-forecast-attacks.svg")

if __name__ == "__main__":
    df, cal = simulate()
    bt, order, sorder, r = legit_backtest(df, cal)
    print("\nLegitimate traffic, monthly rolling-origin forecasts (Jul-Dec 2025)")
    print(pd.DataFrame(legit_metrics(bt)).T.to_string())
    print("\nProposed model, event coefficients (log scale):")
    print(r.params[EVENT_COLS].round(3).to_string())

    at, nb = attack_backtest(df, cal)
    print("\nAttack traffic, one-step-ahead (Jan-Dec 2025)")
    print(pd.DataFrame(attack_metrics(at)).T.to_string())
    print("\nNB model coefficients:")
    print(nb.params.round(3).to_string())

    if "--plots" in sys.argv:
        out = sys.argv[sys.argv.index("--plots") + 1] \
            if len(sys.argv) > sys.argv.index("--plots") + 1 else "."
        plots(df, cal, bt, at, out)
        print(f"\nfigures written to {out}/")
