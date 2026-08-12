# digit-ai-forge-agents-security

Forge de **sécurité agentique** — le juge, séparé du jugé (`forge-agents`). Détail complet :
`README.md`. Mandat d'origine : TF-0111 (`digit-ai-forge-pilot/todo/TODO.jsonl`).

## Garde-fous

- **Invocation sur mandat humain uniquement**, via le pilot. Jamais d'audit spontané d'un
  dépôt tiers depuis cette forge.
- **Outille, ne décide jamais.** Un verdict `FAIL` est un constat localisé, jamais un
  blocage ou une correction automatique.
- **Zéro API tierce payante, zéro dépendance npm.** Deux oracles Node natifs (`.mjs`).
- **Dépôt public : zéro donnée réelle.** Fixtures synthétiques uniquement — aucune donnée
  client, aucun secret, aucun domaine ou identifiant réel.
- **Avant toute modification d'une règle** : rejouer `node oracles/self-test.mjs` (double
  sens — verte passe, rouge échoue pour la bonne raison). Un `✓` sans self-test rejoué
  n'est pas un `✓`.
- **v0 statique + motifs** : ni sandbox d'exécution, ni analyse sémantique. Limites
  détaillées dans `README.md §Limites`, jamais promises au-delà.

## Point d'entrée

```
node oracles/self-test.mjs                      # preuve intégrale
node oracles/oracle-scan-agentdef.mjs <fichier>  # scan statique d'un agent
node oracles/oracle-scan-toolcalls.mjs <journal.jsonl> --perimetre <dossier>  # scan dynamique
```
