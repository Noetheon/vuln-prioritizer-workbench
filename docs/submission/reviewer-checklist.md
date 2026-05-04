# Reviewer Checklist

Diese Checkliste hilft, die finale Abgabe schnell und reproduzierbar zu pruefen.

## Build, Tests, Docs

- [ ] Frontend Build laeuft: `npm --prefix frontend run build`
- [ ] Frontend Lint laeuft: `npm --prefix frontend run lint`
- [ ] Frontend Unit Tests laufen: `npm --prefix frontend run test:unit`
- [ ] UI-Smoke laeuft: `npm --prefix frontend run test -- tests/ui-smoke.spec.ts`
- [ ] Backend Report Contracts laufen:
      `python3 -m pytest -q backend/tests/api/test_template_reports_api.py --no-cov`
- [ ] Backend Smoke Subset laeuft.
- [ ] Docs Hygiene laeuft:
      `python3 -m pytest -q backend/tests/test_docs_hygiene.py --no-cov`
- [ ] MkDocs baut erfolgreich: `python3 -m mkdocs build --clean`
- [ ] `make docs-check` laeuft.

## Scope und Integritaet

- [ ] Keine manuellen Edits in `frontend/src/client/**`.
- [ ] Keine manuellen Edits in `frontend/src/api-client.ts`.
- [ ] Keine ungewollten Backend-Implementierungs-Aenderungen.
- [ ] Keine Aenderungen an `data/attack/**`.
- [ ] Keine Aenderungen an den Contract-Artefakten unter `docs/evidence/`.
- [ ] Keine Screenshots oder grossen Artefakte im Submission-PR.

## Produktclaims

- [ ] VPW wird als Priorisierung bekannter CVEs beschrieben, nicht als Scanner.
- [ ] Scoring wird als transparent und regelbasiert beschrieben.
- [ ] Keine ML-/AI-Blackbox-Claims.
- [ ] CVSS, EPSS, KEV, Asset-Kontext, Provider-Freshness, VEX und Waivers sind
      als sichtbare Signale dokumentiert.
- [ ] Evidence Center, Reports, Manifest und Checksummen sind dokumentiert.

## ATT&CK/TTP Safety

- [ ] Unmapped CVEs bleiben unmapped.
- [ ] Keine heuristische oder LLM-basierte ATT&CK-Inferenz wird behauptet.
- [ ] Curated Mapping wird als defensiver Kontext beschrieben.
- [ ] Kein Exploit-, Payload-, PoC- oder aktives Probing-Material enthalten.
- [ ] Mapped TTP Context wird nicht als lokale Ausnutzung interpretiert.

## Evidence und Demo

- [ ] Final Demo Flow ist verlinkt.
- [ ] Presentation Pack ist verlinkt.
- [ ] Design-System-Evidenz ist verlinkt.
- [ ] Contract-Artefakte unter `docs/evidence/` sind verlinkt.
- [ ] Fallback-Demo ohne Live-System ist moeglich.

## Limitierungen

- [ ] Demo-Daten sind als Beispiel-/Evidenzdaten erkennbar.
- [ ] Public Deployment Hardening bleibt als spaeteres Thema markiert.
- [ ] Detection Coverage wird nicht als Wirksamkeitsbeweis ueberhoeht.
- [ ] Waivers werden als Governance-Kontext, nicht als Risikoloeschung,
      beschrieben.

## Review-Ergebnis

Wenn alle Punkte erfuellt sind, kann das Projekt fuer die aktuelle Phase als
implementation-complete und submission-ready bewertet werden. Weitere
Engineering-Refactorings sollten erst nach der Abgabe priorisiert werden.
