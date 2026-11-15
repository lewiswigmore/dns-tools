# Agent UX article review

**Question:** Is there anything valuable to take from Fuselab Creative's [Agent UX: designing UI for AI agents in 2026](https://fuselabcreative.com/ui-design-for-ai-agents/) for the dns-tools UI SDK redesign?

## Assessment

Only a few general interaction principles transfer. The article is primarily vendor guidance for autonomous agents that take multi-step actions; dns-tools runs user-initiated DNS/RDAP queries and does not delegate actions to an AI agent. Its plan previews, autonomy controls, confidence badges, agent activity panel, memory controls, and decision audit trails would add complexity without solving a current dns-tools problem.

The useful ideas are conventional, and GitHub's [Primer loading guidance](https://primer.style/product/ui-patterns/loading/) and [degraded-experience guidance](https://primer.style/product/ui-patterns/degraded-experiences/) provide more directly applicable implementation advice:

- **Keep users informed during waits.** Show an in-context, accessible loading state when a lookup takes long enough to notice; distinguish a request in progress from completion or failure. If multi-resolver lookups feel slow, consider exposing independently completed results rather than waiting silently for every resolver—but only if partial results remain clear and stable. Primer recommends no indicator under one second, an indeterminate indicator for 1–3 seconds, and determinate progress when a longer duration can be estimated. Existing pages already use explicit loading labels and spinners (for example, `templates/lookup.html`), so this is a consistency/accessibility check rather than a new agent-style UI.
- **Make failures actionable and preserve unaffected results.** Explain the failure at the affected lookup or resolver, retain successful provider responses, and offer a retry when it is meaningful. Don't make an ordinary empty DNS answer look like a network failure. Primer recommends communicating degraded behavior plainly and replacing only the affected content where possible. This fits the existing provider-comparison and partial-result surfaces (`templates/lookup.html`, `templates/dmarc.html`); the article's "what happened / why / next step" is a useful writing checklist, not a proven special formula.
- **Show evidence and limitations beside security conclusions.** Keep the source/resolver and underlying signals inspectable, and label heuristic results as non-authoritative. The existing Fraud Risk Indicators panel already does this by describing its signals as heuristic and advising manual verification (`templates/intel.html`). This is data provenance, not AI reasoning or an audit trail.

## Important caveat

The article's suggestion to surface explanations as a trust-building transparency layer needs qualification. Nielsen Norman Group reports that people rarely click AI citation links, and warns that citations may be inaccurate and step-by-step LLM explanations can be unfaithful to actual model computation ([Explainable AI in Chat Interfaces](https://www.nngroup.com/articles/explainable-ai/)). Therefore, don't add confidence percentages or plausible-sounding reasoning just to make a result feel trustworthy. Show verifiable inputs, sources, and concrete limitations instead. This caveat matters only if an AI-generated explanation or diagnosis feature is introduced.

Fuselab's claims about its client projects and test outcomes (such as binary confidence indicators or expanding autonomy after a specific approval count) are presented as its own experience, not independently substantiated evidence. The article's Gartner projections are not needed to decide this redesign and are not validated here.

## Recommendation

Do not treat the article as a design specification or add agent-specific patterns. For this redesign, use Primer's loading, accessibility, and degraded-state guidance to review the existing lookup flows; keep resolver/source attribution and the current explicit caveat on heuristic fraud signals. Revisit the AI-explanation caveat only if dns-tools adds AI-generated analysis.
