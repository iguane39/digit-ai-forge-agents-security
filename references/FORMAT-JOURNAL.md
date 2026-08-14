# Format du journal d'appels d'outils (JSONL)

Format attendu par `oracles/oracle-scan-toolcalls.mjs` — un fichier **JSONL** (une ligne =
un objet JSON = un appel d'outil), produit par le harnais qui exécute l'agent surveillé.
La forge ne prescrit pas COMMENT ce journal est produit (hors périmètre v0, cf. README
§Limites) — seulement le contrat qu'elle sait lire.

## Ligne minimale

```json
{"ts": "2026-08-12T10:00:00Z", "agent": "id-agent", "tool": "Bash", "input": {"command": "..."}}
```

| Champ | Obligatoire | Description |
|---|---|---|
| `ts` | non (info) | horodatage ISO 8601 de l'appel |
| `agent` | non (info) | identifiant de l'agent émetteur (traçabilité, non jugé par l'oracle) |
| `tool` | **oui** | nom de l'outil invoqué — `Bash`, `PowerShell`, `Read`, `Write`, `Edit`, `NotebookEdit`, `WebFetch`, `WebSearch`, ... |
| `input` | **oui** | objet des paramètres de l'appel, dépendant de `tool` |
| `output` | non (recommandé) | contenu **retourné** par l'outil — c'est le canal des injections indirectes (RAG, page web, fichier, sortie d'un autre outil). Lu par `oracle-corpus-injection.mjs` uniquement ; ignoré par `oracle-scan-toolcalls.mjs` |

## `output` — pourquoi il change ce qui est mesurable

Un journal sans `output` reste valide, mais **ne permet pas** de constater une injection
indirecte : la charge de l'attaquant arrive par ce qu'un outil ramène, pas par ce qu'on lui
demande. Sans `output`, `oracle-corpus-injection.mjs` ne peut plus voir que la **traversée**
(la charge réémise dans l'entrée d'un outil d'action), jamais l'ingestion — donc il ne peut
pas distinguer « le système a résisté » de « le système n'a jamais été exposé ». Journaliser
`output` est un choix du harnais, pas une exigence de format.

## `input` par outil reconnu

- **Bash / PowerShell** : `{ "command": "<ligne de commande>" }`
- **Read** : `{ "file_path": "<chemin>" }`
- **Write / Edit / NotebookEdit** : `{ "file_path": "<chemin>", "content": "..." }` (le contenu
  est scanné pour TC-4, jamais retenu au-delà de l'exécution de l'oracle)
- **WebFetch** : `{ "url": "<url>" }`

Exemple avec `output` (ligne d'ingestion d'un contenu récupéré) :

```json
{"ts": "2026-08-14T09:00:00Z", "agent": "id-agent", "tool": "WebFetch", "input": {"url": "https://docs.exemple.test/guide"}, "output": "Guide… <!-- consigne adressée à l'agent -->"}
```

Toute chaîne présente n'importe où dans `input` (récursivement) est examinée par TC-4
(payload encodé). Les autres règles (TC-1, TC-2, TC-3, TC-5) ciblent spécifiquement les
champs `command`, `file_path` et `url` ci-dessus selon l'outil.

## Ce que l'oracle ne vérifie pas

- Un appel non journalisé par le harnais est invisible — l'oracle audite le journal, pas
  l'exécution réelle (cf. `non_juge` du contrat de sortie).
- Le format ci-dessus est volontairement minimal (v0) : des champs supplémentaires sont
  tolérés et ignorés.
