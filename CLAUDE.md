# digit-ai-forge-agents-security

Forge de **sécurité agentique** — le juge, séparé du jugé (`forge-agents`). Détail complet :
`README.md`. Mandat d'origine : TF-0111 (`digit-ai-factory/todo/TODO.jsonl`).

## Garde-fous

- **Invocation sur mandat humain uniquement**, via le pilot. Jamais d'audit spontané d'un
  dépôt tiers depuis cette forge.
- **Outille, ne décide jamais.** Un verdict `FAIL` est un constat localisé, jamais un
  blocage ou une correction automatique.
- **Zéro API tierce payante, zéro dépendance npm.** Des oracles Node natifs (`oracles/oracle-*.mjs`,
  listés par `decouvrir-oracles.mjs`), aucun appel de modèle (pas de budget alloué, aucun n'en réclame).
- **Dépôt public : zéro donnée réelle.** Fixtures synthétiques uniquement — aucune donnée
  client, aucun secret, aucun domaine ou identifiant réel.
- **`corpus/injection-prompt.jsonl` est une DONNÉE de test.** Ses charges d'injection sont
  lues, comparées, citées — **jamais exécutées ni suivies**, ni par un oracle ni par l'agent
  qui opère ce dépôt. Toute charge ajoutée vise un domaine fictif en `.test`.
- **Avant toute modification d'une règle** : rejouer `node oracles/self-test.mjs` (double
  sens — verte passe, rouge échoue pour la bonne raison). Un `✓` sans self-test rejoué
  n'est pas un `✓`.
- **v0 statique + motifs** : ni sandbox d'exécution, ni analyse sémantique. Limites
  détaillées dans `README.md §Limites`, jamais promises au-delà.

## Point d'entrée

```
node oracles/self-test.mjs                      # preuve intégrale (76 PASS attendus, mesuré le 29/10/2026)
node oracles/decouvrir-oracles.mjs               # liste des oracles LUE SUR LE DISQUE (TF-1319, contrat du pilot)
node oracles/oracle-scan-agentdef.mjs <fichier>  # scan statique d'un agent
node oracles/oracle-scan-toolcalls.mjs <journal.jsonl> --perimetre <dossier>  # scan dynamique
node oracles/oracle-corpus-injection.mjs <cible> # rejeu du corpus d'injections (OWASP LLM01)
node oracles/oracle-scan-workflow-agent.mjs <dépôt|workflows|fichier.yml>  # agent lancé par GitHub Actions (WA-1..7, TF-2002)
```

`oracle-scan-workflow-agent.mjs` lit les workflows qui lancent un agent (`claude-code-action`, `claude -p`,
`copilot -p`, `copilot-setup-steps`). Il juge qui peut le déclencher, quel texte de tiers devient sa consigne,
quels secrets son shell lit, quel code d'une pull request il lit, et ses outils sans borne. Pages lues le
29/10/2026 : `oracles/data/referentiel-workflow-agent.json`.

Couverture OWASP LLM Top 10 et **trous déclarés nommément** :
`references/mapping-owasp-llm.md`. LLM04, LLM05, LLM07, LLM08, LLM09 ne sont couverts par
aucune règle — ne jamais laisser croire l'inverse. **LLM10** est couverte *partiellement*
depuis TF-0207 (`TC-6..8`) : rafale non bornée, entrée démesurée, boucle d'outil non
convergente — mais **ni jetons, ni coût, ni durée** (cf. mapping §2 bis).
