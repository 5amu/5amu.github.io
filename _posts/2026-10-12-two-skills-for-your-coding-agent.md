---
title: "Two Skills for Your Coding Agent: unslop and interview"
description: "I published two agent skills, installable with one npx command. unslop strips the machine-written tells out of prose, and interview grills you about a plan before the agent builds the wrong thing. What each does, with a before and after."
categories:
  - dev
  - ai
image: /assets/img/skills-icon.png
---
I keep two text files that I paste into every coding agent I use. They are now published as [agent skills](/skills/) you can install with the [`skills`](https://github.com/vercel-labs/skills) CLI:

```sh
npx skills add {{ site.url }}{{ site.baseurl }}/skills/unslop
npx skills add {{ site.url }}{{ site.baseurl }}/skills/interview
```

A skill is a `SKILL.md` the agent reads when a task matches its description. Claude Code, Codex, Cursor and most of the others support the format. There is nothing to configure and no server to run.

## unslop

Agents write prose the same way every time, and you can tell. Em dashes everywhere. "It's not X, it's Y." A bold label in front of every bullet. A closing paragraph that restates the post. `unslop` is a list of 39 numbered patterns like these, each with its fix, plus the rule that matters most: never invent a fact to sound human. If the source has no numbers, the rewrite has no numbers either.

It triggers on its own whenever the agent writes something a person will read, like a README, a PR description, release notes or an email. You can also point it at existing text ("unslop this") and it returns the smallest diff that removes the tells while keeping your voice and your opinions.

Same prompt, "write the PR description for the retry module", without the skill:

> ### 🚀 Add retry module with exponential backoff
>
> This PR introduces a **robust** retry mechanism designed to seamlessly handle transient failures — network timeouts, rate limits, and more. It's not just about retrying; it's about retrying *smartly*.
>
> **Key changes:**
> - **Exponential backoff:** Implements exponential backoff with jitter
> - **Configurable:** Max attempts and base delay are configurable
>
> The result? Fewer 3am pages. Let me know if you'd like any changes!

With it:

> Add a retry module
>
> `retry.Do` retries a failed call with exponential backoff and jitter. It retries on timeouts and HTTP 429 and gives up after `MaxAttempts` (default 5, base delay 200ms). Other errors return immediately.
>
> The HTTP client in `fetch/` now goes through it. No behaviour change for callers that don't opt in.

The second one read the code. The first one read a thousand PR descriptions.

## interview

The other failure mode is the opposite one. You describe a feature in two sentences, the agent says "Great, I'll build that", and twenty minutes later you have a working implementation of something you didn't mean. Every ambiguity got resolved silently, by guessing.

`interview` is manual only (`/interview` in Claude Code), so the agent never pulls it in by itself. It first reads what the repo already says, the README, `docs/` and the code the plan touches, so it never asks what it can look up. Then it asks in rounds of at most four multiple-choice questions. Each has a recommended answer with a one-line reason, one or two real alternatives with their trade-off, and a write-your-own option. Answers unblock the next questions. When nothing is left to decide it writes the agreed plan to `docs/PROJECT.md`: goals, non-goals, a glossary of the terms you settled on, and each decision with its reason.

Prompt: "add rate limiting to the API". Without the skill, the agent picks a token bucket, keys it by IP, keeps the counters in memory, returns 429 and tells you it's done. Those were four decisions, and you made none of them.

With `/interview`, round one:

> **Q1. Where does the limit apply?**
> - A. Per API key (recommended): every route already requires one
> - B. Per client IP: works for unauthenticated routes, but clients behind the same NAT get throttled together
> - C. Write your own answer
>
> **Q2. Where do the counters live?**
> - A. Redis (recommended): the deployment runs three replicas, and in-memory counters would give each one its own budget
> - B. In memory: simplest, correct only with a single instance
> - C. Write your own answer
>
> **Q3. What happens on a hit?**
> - A. 429 with `Retry-After` (recommended): matches what `/export` already does
> - B. Queue the request for up to N seconds, then 429
> - C. Write your own answer

It found the three replicas and the existing 429 behaviour on its own before asking. Facts are its job, decisions are yours.

The format is adapted from Matt Pocock's [grilling skills](https://github.com/mattpocock/skills) (MIT).

## Where they live

Both skills are at [/skills/](/skills/), with the full `SKILL.md` and a search box. If you catch a tell that `unslop` misses, open an issue on [the site's repo](https://github.com/5amu/5amu.github.io). The rules are numbered and never renumbered, so a new one goes at the end.
