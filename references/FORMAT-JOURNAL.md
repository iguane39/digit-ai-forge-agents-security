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

## `input` par outil reconnu

- **Bash / PowerShell** : `{ "command": "<ligne de commande>" }`
- **Read** : `{ "file_path": "<chemin>" }`
- **Write / Edit / NotebookEdit** : `{ "file_path": "<chemin>", "content": "..." }` (le contenu
  est scanné pour TC-4, jamais retenu au-delà de l'exécution de l'oracle)
- **WebFetch** : `{ "url": "<url>" }`

Toute chaîne présente n'importe où dans `input` (récursivement) est examinée par TC-4
(payload encodé). Les autres règles (TC-1, TC-2, TC-3, TC-5) ciblent spécifiquement les
champs `command`, `file_path` et `url` ci-dessus selon l'outil.

## Ce que l'oracle ne vérifie pas

- Un appel non journalisé par le harnais est invisible — l'oracle audite le journal, pas
  l'exécution réelle (cf. `non_juge` du contrat de sortie).
- Le format ci-dessus est volontairement minimal (v0) : des champs supplémentaires sont
  tolérés et ignorés.
