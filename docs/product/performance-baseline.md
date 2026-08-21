# Performance baseline (Product v1)

No new scale subsystem. Documented smoke limits:

| Scenario | Target |
|----------|--------|
| Empty offline `assess` (init-only project) | < 2 seconds wall clock (`performance_baseline.rs`) |
| Demo fixture assess (vulnerable/secure/agentic) | Suitable for local CI smoke; not a load test |
| Report HTML render | Included in assess; refresh via `report --refresh` |

Memory: not instrumented in v1; operators should treat assessments as developer-scale offline fixtures.

Incremental revalidation timing remains owned by Cycle 010 continuous engine (plan-only in product assess when fixture provided).
