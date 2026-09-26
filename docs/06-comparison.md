# Comparing the Two Approaches

| Item | Details |
|---|---|
| Date | 2026-09-26 |
| Compared | Approach A: AWS Network Firewall (managed) / Approach B: Suricata inline IPS on EC2 (self-operated) |
| Evidence | Phase 8–11 deployments, measurement tool results, `ADR-022`–`ADR-027`, `05-verification.md` |

## Conclusion

With the same rules, both approaches blocked almost exactly the same attacks. The difference was in operations, not detection. The managed firewall costs about four times as much per hour, but AWS takes care of forwarding, failure handling, and the engine. The self-operated one is cheaper and faster to bring up, but I had to build and own all of that myself.

For an environment like this one, which is created for a test and destroyed afterwards, self-operated is the better fit. It comes up in about a minute, so repeated measurements are easy, and when something goes wrong the configuration and counters show why. For a service that stays up, I would recommend managed. Bringing the self-operated setup to production level means running several instances behind a Gateway Load Balancer with auto scaling, and at that point the gap in both cost and complexity narrows considerably (`03-architecture.md` section 5.1).

Whichever approach is used, attacks inside encrypted web requests were invisible at the network layer. HTTPS attacks were stopped by the WAF, which terminates TLS. What the network layer reliably did was filter some plaintext requests first and control outbound traffic from inside the VPC. These conclusions come from one Availability Zone, 15 custom rules, and 515 measurement requests; section 7 covers the limits.

---

## 1. What was held constant

Both approaches load the same rule file (`rules/attacks.rules`, 15 rules), and both use the Suricata engine. I did not use the managed firewall's AWS-managed rule groups: if only one side had them, a difference in results could come from either the operating model or the rules, and there would be no way to tell which (`ADR-022`). The network layout and paths are also identical. Only the route target changes, from the firewall endpoint to the Suricata instance's network interface (`ADR-026`).

Each run sent the same 515 requests over both plaintext (80) and encrypted (443) paths with the same tool. Every request carried an ID that could be looked up in each layer's logs, so I could tell, request by request, which layer blocked what (`ADR-020`).

## 2. Detection

| | Approach A (managed) | Approach B (self-operated) |
|---|---|---|
| Requests blocked on the plaintext path | 17 | 16 |
| Requests blocked on the encrypted path | 0 | 0 |
| False positives on real traffic | 0 | 0 |
| Outbound marker request | Blocked | Blocked |

The two approaches disagreed on one request. The same cross-site scripting payload was caught by both when placed in the URL path, but only by the managed firewall when placed in the query string. The `=` the rule looks for was encoded as `%3D` in that request, so my working explanation is that the two engines decode the query string differently by default. I did not confirm this by changing settings. The managed firewall does not publish its Suricata version or configuration, so on that side any explanation stays a guess.

Most requests blocked at the network layer on the plaintext path were ones the WAF would have blocked anyway. The combined detection rate of both layers was only about 1 percentage point higher than the WAF alone on the encrypted path. The network-layer rules are few and simple; the WAF did nearly all of the work against web attacks.

The WAF's 44.7% detection rate varies sharply with where the attack is placed.

| Attack location (HTTPS, 309 attacks) | WAF detection rate |
|---|---|
| Query string | 82.1% |
| JSON body | 78.2% |
| URL path | 14.1% |
| Custom header | 2.7% |

The URL path and the custom header are places this app does not read as input. The app is a single-page application that returns the same page for any path, and the header name is one no application uses. On the two locations the app actually reads, the WAF blocked 80.1%, including every SQL injection, NoSQL injection, remote command execution, and XXE payload. Widening the rules to inspect paths and headers for attack patterns would raise the headline number, but it would not stop any additional real attack and would only add false positives, so I did not. LDAP injection was not detected anywhere, because the rule set (CRS 3.3.5) has very few rules for it; this app has no LDAP.

## 3. What each approach required to run

The managed firewall took six resources: a rule group, a policy, the firewall, two log groups, and a logging configuration. In exchange, some things had to be done the service's way. It does not accept line continuations in rule files, so rules had to be joined into single lines before being passed in. Rule group capacity cannot be changed after creation, so I sized it generously up front. While the account was on the free plan, the service could not be used at all.

The self-operated approach meant building, one by one, the things AWS otherwise does. I disabled the source/destination check so the instance would accept packets not addressed to it, enabled kernel forwarding, turned off the ICMP redirects that a single-interface router sends, and queued only forwarded traffic for Suricata to judge. The package's default service runs in passive mode, which only sees copies of packets, so I wrote a separate inline service. Even then, if Suricata came up in passive mode or a single rule failed to parse, the service would look healthy while blocking nothing. The boot script therefore checks that the queue is actually bound and that every rule loaded, and stops if either check fails (`ADR-027`).

Self-operation also forced some decisions that never came up with the managed firewall. The instance needs a public address for its own traffic, and a security group cannot tell forwarded traffic from traffic addressed to the instance, so ports 80 and 443 had to be narrowed to the operator's address. That in turn blocked the WAF's outbound 443, so another rule was needed. With the rule file embedded in the boot script, the user data came within 1 KB of the 16 KB limit; compressing it solved that.

## 4. When inspection stops

With the managed firewall, you cannot choose whether traffic passes or is dropped when inspection fails. AWS keeps the endpoint in each Availability Zone running, and that decision is neither visible nor configurable.

For the self-operated approach I chose fail-closed (`ADR-012`) and tested it by stopping Suricata. Responses from the WAF stopped on both plaintext and encrypted paths, while management access to the Suricata instance itself stayed up, so I could log in and restart it. What I had not expected was that management access to the app was lost too: the app's outbound connections also go through NAT and then Suricata. Even after the restart, commands to the app stalled for about six minutes. In IPS mode, Suricata 7 drops connections it did not see from the start, and the agent connections established before the restart fell into that category. The counter `ips.drop_reason.stream_midstream` recorded it. A command that stalled right after switching routes on the managed firewall looks like the same effect, but the managed firewall's internal counters are not visible, so that remains a guess.

On the self-operated side, the single instance is a single point of failure for everything. This environment has no availability requirement, so I left it (`NFR-05`), but in production redundancy would come first.

## 5. Cost and time

| | Approach A (managed) | Approach B (self-operated) |
|---|---|---|
| Inspection layer up | 5 min 45 s | ~1 min |
| Full create | ~6 min | ~2 min |
| Full destroy | ~5 min 30 s | ~80 s |
| Hourly cost, everything running | ~$0.50 (endpoint $0.395) | ~$0.12 |
| Hours per month on a ₩50,000 budget | ~70 | ~290 |

Costs are calculated from Seoul region on-demand prices at 1,400 KRW per USD. Billing data lags by about a day, so usage on the day of testing could not be queried.

Turning on TLS inspection in the managed firewall would make the encrypted path visible too, but the advanced inspection endpoint adds $0.792 an hour, and inbound inspection requires handing the server's private key to Certificate Manager, so I did not use it (`ADR-025`).

## 6. Finding the cause of a problem

Managed firewall alerts land in CloudWatch directly, but they arrived anywhere from 20 seconds to over a minute late. Once, the measurement tool stopped before they arrived and counted zero alerts. Configuration and counters are not visible, so when a result looked wrong I had to infer the cause from the shape of the logs.

With self-operation, alerts are written to disk immediately, and the command line, configuration files, and statistics counters are all visible. On the other hand, getting those logs into CloudWatch meant installing the agent myself (`ADR-028`). Because both approaches use the same engine, their alerts share field names; one side just wraps them in an extra layer. That made it possible to read both with a single query (`ADR-030`).

## 7. Limits of this conclusion

- Measured in a single Availability Zone. Availability differences between the two were compared on paper only; failover was not measured.
- The network layer uses 15 custom rules. Absolute detection rates say nothing about product performance and are only useful for comparing the two approaches.
- 515 requests per run, and most comparisons rest on one or two runs per approach. Differences of one or two requests can shift between runs (approach B produced both 15 and 16).
- The Suricata version and default configuration used by the managed firewall could not be checked.
- Costs are based on unit prices, not on billed amounts.
