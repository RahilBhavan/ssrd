# Labeling guide

Both labelers read this before starting, so labels mean the same thing and Cohen's kappa measures
real agreement. You only see sanitized text in `ssrd review`. **Never open a flagged domain in a
browser.**

Ask one question per page: **is this page a fake investment platform built from a reusable scam
template?** The matched kit name and signals are context, not the answer.

| Key | Label | Use when | Typical signs |
|---|---|---|---|
| `s` | scam-kit | The page is a fake investment, trading, mining or "AI bot" platform. | Guaranteed or daily returns, "investment plans", deposit tiers, sign-up/login funnel with no real company behind it, a fake regulator or licence claim, a crypto deposit address, a copy-pasted template seen on other alerts. |
| `n` | not-scam | A real business, blog, shop, school, agency or personal site, even one about finance. | A specific company, address, team and products; nothing asks you to deposit for returns. |
| `d` | decoy-cloaked | The page hides its real content. | "Human verification" or "you will be redirected" gates; a harmless decoy page on a domain whose name suggests a trading platform. |
| `p` | parked | No site yet. | Registrar "domain expired", hosting default page, "coming soon", domain-for-sale. |
| `e` | error | The capture failed. | 404/500 pages, empty captures. |
| `u` | unsure | You can't tell from the text. | Fake-bank templates, thin trading pages, sites that might be real brokers. Use it sparingly. |

Rules:

1. Judge the page, not the domain name.
2. Finance is not suspicious by itself: a real wealth manager or broker is `n`.
3. Gambling, casino and "earn money" app pages are `n` unless they sell an investment platform.
4. Fake banks (online-banking templates with no real bank behind them) are `u`, not `s`: they are
   a different scam, not an investment kit.
5. Rahil's queue shows the assistant's suggestion; Enter accepts it. Read the page before
   accepting. The second labeler always uses `--blind`.
6. Add a short note when the call was hard. Notes help when we discuss disagreements later.
