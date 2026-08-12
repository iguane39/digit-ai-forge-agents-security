# digit-ai-forge-agents-security

Forge dédiée à la **sécurité agentique** — le contrôle des agents et de leurs invocations
d'outils, séparé de la forge qui les construit (`forge-agents`). Née du mandat TF-0111
(décision humaine du 12/08/2026, registre `digit-ai-forge-pilot/todo/TODO.jsonl`).

## Catalogue de services

> Section proposée par la campagne « catalogues » du pilot (2026-08-12) — générée depuis
> la source unique `catalogues/catalogue.jsonl` du pilot (v1.3.0, challengée état de
> l'art le 12/08/2026). **prouvé** = preuve exécutée ; *déclaré* = méthode documentée seulement.

| Service | Intention (« je veux… ») | Point d'entrée | Statut |
|---|---|---|---|
| **Scanner un agent (statique)** | vérifier qu'un agent défini ne porte pas de capacités dangereuses | `node oracles\oracle-scan-agentdef.mjs <def>` | prouvé (experimental) |
| **Scanner les appels d'outils (dynamique)** | détecter les patterns d'attaque dans un journal d'exécution d'agent | `node oracles\oracle-scan-toolcalls.mjs <journal.jsonl> --perimetre <racine>` | prouvé (experimental) |

Le catalogue consolidé des dix forges vit chez le pilot :
[digit-ai-forge-pilot/catalogues/CATALOGUES.md](https://github.com/iguane39/digit-ai-forge-pilot/blob/main/catalogues/CATALOGUES.md).

## Doctrine

- **Le juge ne vit pas chez le jugé.** `forge-agents` construit des agents et outille leur
  cohérence structurelle (gates anti-serial-collapse, oracles de livrables). Elle ne peut
  pas être son propre contrôle de sécurité — d'où une forge séparée.
- **Invocation sur mandat humain**, via le pilot (`digit-ai-forge-pilot`). Cette forge
  n'audite jamais spontanément un dépôt tiers.
- **Elle outille, ne décide jamais.** Un verdict `FAIL` est un constat argumenté et
  localisé — jamais un blocage automatique d'un run, jamais une correction appliquée à la
  place d'un humain.
- **Zéro API tierce payante.** Zéro dépendance npm. Deux scripts Node natifs (`.mjs`),
  aucune installation.
- **Zéro donnée réelle.** Dépôt public : toutes les fixtures sont synthétiques (domaines,
  identifiants, chemins fictifs) — aucune donnée client, aucun secret réel.

## Catalogue v0 — statut prouvé

| Service | Statut | Preuve |
|---|---|---|
| `oracles/oracle-scan-agentdef.mjs` — scan **statique** d'un agent.def ou d'un subagent compilé | **prouvé** | 9 fixtures (`fixtures/agentdef/`), rejouées par `self-test.mjs` |
| `oracles/oracle-scan-toolcalls.mjs` — scan **dynamique** d'un journal JSONL d'appels d'outils | **prouvé** | 11 fixtures JSONL + 1 allowlist de domaines (`fixtures/toolcalls/`), rejouées par `self-test.mjs` |
| `oracles/self-test.mjs` — rejeu intégral à double sens (vert doit passer, rouge doit échouer *pour la bonne raison*) | **prouvé** | 24/24 PASS à la dernière exécution connue (rejouer avant de faire confiance) |

« Prouvé » signifie : chaque règle a une fixture verte qui passe et une fixture rouge
voisine qui échoue pour la raison attendue (code `regle` vérifié, pas seulement le verdict
global). Un service sans cette preuve n'apparaîtrait pas ici.

### `oracle-scan-agentdef.mjs` — 4 familles de règles

| Règle | Détecte |
|---|---|
| `CAP-1` | Combinaison de capacités dangereuse : réseau + écriture filesystem + lecture cumulées par le même agent (surface d'exfiltration complète — lire un secret, l'exfiltrer, couvrir ses traces) |
| `CAP-2` | Outil déclaré absent du référentiel fermé (`oracles/data/referentiel-outils.json`) — supply-chain, typosquat, capacité hallucinée |
| `CAP-3` | Permissions plus larges que le mandat déclaré (mandat de lecture/revue, outils d'écriture ou d'exécution accordés) |
| `CAP-4` | Motif d'instruction d'exfiltration ou d'injection dans le texte de l'agent (mandat, arbitre, corps du prompt compilé) |

Formats lus : agent.def source (YAML, sous-ensemble documenté par `forge-agents`) et
subagent **compilé** Claude Code (`.claude/agents/<id>.md`, frontmatter + prompt) — détection
automatique par la présence d'un frontmatter `---`.

```
node oracles/oracle-scan-agentdef.mjs <fichier.yaml|fichier.md> [--json-only]
```

### `oracle-scan-toolcalls.mjs` — 5 familles de motifs d'attaque

| Règle | Détecte |
|---|---|
| `TC-1` | Exfiltration réseau : curl/wget/WebFetch vers un domaine hors allowlist, ou téléchargement distant directement exécuté (pipe vers `sh`/`bash`/`powershell`) |
| `TC-2` | Destruction hors périmètre : `rm -rf` (ou équivalent) ciblant un chemin hors du périmètre déclaré ou une racine dangereuse (`/`, `~`, `C:\`, `/etc`, ...) |
| `TC-3` | Lecture de secrets : `.env`, clés privées, `credentials`, `.ssh/`, `.aws/credentials` |
| `TC-4` | Payload encodé : chaîne base64 anormalement longue (≥ 120 caractères), indice d'obfuscation |
| `TC-5` | Écriture hors périmètre déclaré : `Write`/`Edit`/`NotebookEdit` ciblant un chemin hors périmètre |

Format du journal : voir `references/FORMAT-JOURNAL.md`.

```
node oracles/oracle-scan-toolcalls.mjs <journal.jsonl> --perimetre <dossier> [--domaines <fichier.json>] [--json-only]
```

`--perimetre` est **obligatoire** — aucune frontière de sécurité n'est devinée par défaut
(même doctrine que `forge-ops --seuils` pour le rollback). `--domaines` est optionnel ; à
défaut, l'allowlist réseau est **vide** : tout domaine externe est donc signalé par défaut
(deny-by-default, posture assumée — pas un oubli).

### Contrat de sortie (les deux oracles)

```json
{ "oracle": "...", "version": "0.1.0", "artefact": "...", "verdict": "PASS|FAIL|SKIP|donnees_insuffisantes",
  "findings": [{ "sev": "bloquant|majeur|mineur|info", "regle": "CAP-1", "msg": "...", "where": "..." }],
  "non_juge": ["..."] }
```

Exit `0` = PASS, `1` = FAIL, `2` = SKIP / `donnees_insuffisantes`.

## Rejouer les preuves

```
node oracles/self-test.mjs
```

Sortie attendue : `24 PASS, 0 FAIL`. À rejouer après toute modification d'une règle ou
d'une fixture — un `✓` sans self-test rejoué n'est pas un `✓`.

## Limites explicites (ce que la v0 n'est pas)

- **Pas de sandbox d'exécution.** Aucun des deux oracles n'exécute l'agent scanné ni les
  commandes du journal — analyse texte/structure uniquement. Un agent qui obfusque au-delà
  des motifs lexicaux couverts (encodages autres que base64, indirection via variable,
  commande construite dynamiquement) n'est pas détecté.
- **Pas d'analyse sémantique.** `CAP-3` et `CAP-4` reposent sur des motifs lexicaux
  (mots-clés, regex), pas sur une compréhension du sens — faux négatifs et faux positifs
  possibles en marge, mesurés par les fixtures mais non exhaustifs.
- **Pas de complétude du journal.** `oracle-scan-toolcalls.mjs` audite ce qui est journalisé
  ; un appel d'outil non tracé par le harnais est invisible.
- **Référentiel d'outils v0 figé à la main** (`oracles/data/referentiel-outils.json`) — à
  tenir à jour au fil des harnais réels, pas de découverte automatique.
- **Pas de red-teaming automatisé** (génération d'attaques, fuzzing de prompts) ni de
  **scan runtime branché sur le harnais** (interception en direct des appels d'outils
  pendant un run) — restes explicites, jamais promis au catalogue ci-dessus.
- **Pas de décision.** Le verdict `FAIL` ne bloque rien tout seul — un humain ou un run
  amont décide de la suite via le pilot.

## Arborescence

```
oracles/
  oracle-scan-agentdef.mjs     scan statique agent.def / subagent compilé
  oracle-scan-toolcalls.mjs    scan dynamique journal JSONL d'appels d'outils
  self-test.mjs                rejeu intégral à double sens
  data/referentiel-outils.json catalogue fermé des outils reconnus
fixtures/
  agentdef/                    9 fixtures (vertes + rouges) pour oracle-scan-agentdef
  toolcalls/                   11 fixtures JSONL (vertes + rouges) + allowlist de domaines
references/
  FORMAT-JOURNAL.md            schéma documenté du journal JSONL
```
