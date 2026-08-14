# Mapping des règles de la forge → OWASP Top 10 for LLM Applications

Rattache chaque règle **exécutée** de cette forge (`CAP-1..4`, `TC-1..5`, `INJ-1..3`) aux
catégories du **OWASP Top 10 for LLM Applications, édition 2025** (projet OWASP GenAI
Security), puis **déclare nommément** ce qu'aucune règle ne couvre.

> Règle de rédaction de ce document : *une couverture partielle qui se tait est pire qu'un
> trou déclaré.* Aucune case n'est laissée implicite — chaque catégorie a une ligne, y
> compris celles où la réponse est « rien ».

**Référentiel employé** — les dix intitulés ci-dessous sont ceux de l'édition 2025, relevés
à la source du projet OWASP GenAI (`genai.owasp.org/llm-top-10/`) le 14/08/2026. Cette forge
ne suit pas la version du référentiel automatiquement : à toute réédition OWASP, ce document
est à rejouer à la main (dette assumée, cf. README §Limites).

| Id | Intitulé (2025) |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

---

## 1. Règle → catégorie(s)

« Principale » = ce que la règle vise ; « touchée » = ce qu'elle effleure sans le mesurer
complètement. Le **verbe** dit ce qui est réellement observé, pour qu'aucun lecteur ne
confonde la règle avec la catégorie entière.

| Règle | Oracle | Ce qu'elle observe réellement | Principale | Touchée |
|---|---|---|---|---|
| `CAP-1` | `oracle-scan-agentdef` | cumul réseau + écriture + lecture dans le jeu d'outils déclaré d'un agent | **LLM06** | LLM02 |
| `CAP-2` | `oracle-scan-agentdef` | outil déclaré absent du référentiel fermé (typosquat, capacité hallucinée) | **LLM03** | LLM06 |
| `CAP-3` | `oracle-scan-agentdef` | permissions accordées plus larges que le mandat écrit (moindre capacité) | **LLM06** | — |
| `CAP-4` | `oracle-scan-agentdef` | motif lexical d'exfiltration ou d'injection dans le texte de l'agent | **LLM01** | LLM02 |
| `TC-1` | `oracle-scan-toolcalls` | appel réseau sortant hors allowlist, ou téléchargement distant exécuté (pipe shell) | **LLM02** | LLM05, LLM06 |
| `TC-2` | `oracle-scan-toolcalls` | suppression récursive forcée hors du périmètre déclaré | **LLM06** | — |
| `TC-3` | `oracle-scan-toolcalls` | lecture d'un chemin de secret (`.env`, clés privées, `credentials`) | **LLM02** | LLM07 |
| `TC-4` | `oracle-scan-toolcalls` | chaîne encodée anormalement longue dans une entrée d'outil (obfuscation) | **LLM01** | LLM02 |
| `TC-5` | `oracle-scan-toolcalls` | écriture hors du périmètre déclaré | **LLM06** | LLM04 |
| `INJ-1` | `oracle-corpus-injection` | charge du corpus portée **en clair** par une définition d'agent | **LLM01** | LLM06 |
| `INJ-2` | `oracle-corpus-injection` | charge (ou son marqueur) retrouvée dans l'entrée d'un outil d'**action** — traversée | **LLM01** | LLM02, LLM05, LLM06 |
| `INJ-3` | `oracle-corpus-injection` | charge ingérée puis **non** réémise dans un acte — trace du comportement sain (info, jamais un défaut) | **LLM01** | — |

### Lecture inverse — catégorie → règles

| Catégorie | Règles qui la touchent | Niveau réel de couverture |
|---|---|---|
| **LLM01** Prompt Injection | CAP-4, TC-4, INJ-1, INJ-2, INJ-3 | **partielle, mesurée** — 34 charges du corpus rejouées sur artefact statique ; ni modèle vivant, ni reformulations hors corpus |
| **LLM02** Sensitive Information Disclosure | TC-1, TC-3, CAP-1, CAP-4, TC-4, INJ-2 | **partielle** — chemins de secrets et sorties réseau observés ; aucune détection de secret **dans le contenu** transmis (regex de chemin, pas de classifieur de donnée) |
| **LLM03** Supply Chain | CAP-2 | **marginale** — référentiel d'outils fermé uniquement ; ni provenance de modèle, ni intégrité de dépendance, ni signature de plugin/MCP |
| **LLM04** Data and Model Poisoning | TC-5 (effleuré), INJ-1 (effleuré) | **NON COUVERTE** — voir §2 |
| **LLM05** Improper Output Handling | TC-1 (pipe vers interpréteur), INJ-2 | **marginale** — un seul puits aval couvert (le shell) ; aucun contrôle d'assainissement vers HTML, SQL, rendu markdown, navigateur |
| **LLM06** Excessive Agency | CAP-1, CAP-2, CAP-3, TC-2, TC-5, INJ-2 | **la mieux couverte** — surface déclarée (statique) + périmètre observé (dynamique) ; reste hors champ : les actions à effet externe non journalisées |
| **LLM07** System Prompt Leakage | TC-3 (effleuré), charges INJ-D-03/D-04 (tentatives) | **NON COUVERTE** — voir §2 |
| **LLM08** Vector and Embedding Weaknesses | charge INJ-I-12 (tentative) | **NON COUVERTE** — voir §2 |
| **LLM09** Misinformation | charges INJ-I-06/I-12/I-17 (tentatives) | **NON COUVERTE** — voir §2 |
| **LLM10** Unbounded Consumption | aucune | **NON COUVERTE** — voir §2 |

---

## 2. Catégories NON couvertes — déclaration nominale

Aucune règle de cette forge ne rend de verdict sur les catégories suivantes. Un run qui
passe les trois oracles au vert **n'a rien dit** de ces cinq risques.

| Catégorie | Ce qui manque | Pourquoi, aujourd'hui |
|---|---|---|
| **LLM04** Data and Model Poisoning | aucun oracle n'inspecte un jeu d'entraînement, un jeu de fine-tuning, un index RAG ni une mémoire persistante | ces artefacts ne sont pas dans le périmètre v0 (définitions d'agents + journaux d'outils). `TC-5` détecte une écriture hors périmètre, pas l'empoisonnement d'un corpus dans le périmètre. Le corpus contient les charges INJ-D-14 et INJ-I-11 qui **tentent** l'empoisonnement — leur détection resterait une détection LLM01, pas une mesure LLM04 |
| **LLM05** Improper Output Handling | aucun contrôle de l'assainissement de la sortie du modèle avant son puits aval (HTML, SQL, shell, rendu markdown, navigateur) | seul le puits « shell » est effleuré par `TC-1` (pipe vers interpréteur). Les charges INJ-I-07 et INJ-I-08 (image et lien markdown exfiltrants) ciblent précisément ce trou : elles sont **écrites au corpus mais leur détection n'est possible que si l'artefact les trace** — le rendu côté client n'est pas journalisé |
| **LLM07** System Prompt Leakage | aucune règle ne compare une sortie au prompt système pour détecter une fuite | l'oracle statique ne connaît pas le prompt système effectif du harnais ; les journaux v0 ne portent pas les réponses en langage naturel. Les charges INJ-D-03 et INJ-D-04 sont au corpus comme **tentatives**, pas comme mesure de fuite |
| **LLM08** Vector and Embedding Weaknesses | aucun accès à un index vectoriel, aucune mesure de cloisonnement multi-locataire ni d'anomalie de récupération | aucun artefact de ce type n'entre dans les formats lus. La charge INJ-I-12 (document « aimant ») documente le risque sans le mesurer |
| **LLM09** Misinformation | aucune vérification factuelle des sorties | exigerait un jugement sémantique, donc un modèle : incompatible avec la contrainte « zéro API tierce payante, zéro budget » de cette forge. À porter par une autre forge (forge-tests / forge-data) si le besoin est mandaté |
| **LLM10** Unbounded Consumption | aucun comptage de jetons, de boucles, de durée ou de coût | le format de journal v0 ne porte ni volumétrie ni coût. Ajout possible sans modèle (donc gratuit) si le harnais journalise ces champs — candidat identifié, non fait ici |

**LLM03** figure au §1 comme « marginale » et non comme couverte : `CAP-2` ne vérifie qu'un
nom d'outil contre une liste tenue à la main. Ni provenance de modèle, ni intégrité de
dépendance, ni signature de serveur MCP ne sont contrôlées.

---

## 3. Ce que le corpus ajoute, et ce qu'il n'ajoute pas

`corpus/injection-prompt.jsonl` — 34 charges (17 **directes**, entrée utilisateur ;
17 **indirectes**, contenu récupéré / page web / fichier joint / sortie d'outil).

**Ajoute** : LLM01 passe d'une détection par motifs génériques (`CAP-4`, 5 regex) à un
**rejeu nommé et versionné**, où chaque constat cite l'identifiant de la charge, sa famille,
son effet recherché, sa catégorie OWASP et le comportement attendu d'un système sain.

**N'ajoute pas** : le corpus ne teste **aucun modèle**. Il est rejoué contre un artefact
statique (définition d'agent, journal d'appels d'outils) et ne peut donc constater qu'une
trace laissée — pas une résistance. Un système qui refuse la charge sans laisser de trace et
un système qui n'a jamais vu la charge sont indiscernables pour cet oracle.

### Répartition des charges par catégorie OWASP visée

| Catégorie visée par la charge | Charges |
|---|---|
| LLM01 (seule ou principale) | 29 charges sur 34 — les 5 restantes (INJ-D-04, INJ-D-09, INJ-I-07, INJ-I-08, INJ-I-12) visent d'abord LLM05/LLM07/LLM08 |
| LLM02 (secondaire) | 7 — INJ-D-05, INJ-D-11, INJ-I-01, INJ-I-02, INJ-I-07, INJ-I-08, INJ-I-10 |
| LLM03 | 2 — INJ-I-03, INJ-I-09 |
| LLM04 | 2 — INJ-D-14, INJ-I-11 |
| LLM05 | 3 — INJ-D-09, INJ-I-07, INJ-I-08 |
| LLM06 | 8 — INJ-D-08, INJ-D-09, INJ-D-15, INJ-D-17, INJ-I-04, INJ-I-14, INJ-I-15, INJ-I-16 |
| LLM07 | 2 — INJ-D-03, INJ-D-04 |
| LLM08 | 1 — INJ-I-12 |
| LLM09 | 3 — INJ-I-06, INJ-I-12, INJ-I-17 |
| LLM10 | **aucune** — hors modèle de menace du corpus v0 |

Une charge peut viser plusieurs catégories : la somme de la colonne dépasse 34.

**Par effet recherché** : contournement de consigne 11, exfiltration 9, escalade de
permission 7, appel d'outil non voulu 7.
**Par vecteur** : entrée utilisateur 17 (directes) · document récupéré 6 · fichier joint 5 ·
sortie d'outil 4 · page web 2 (indirectes).

> `INJ-D-06` porte sa charge sous forme **encodée** (base64) : son marqueur d'effet
> `CANARI-D06` n'apparaît donc pas littéralement dans le champ `charge`, il n'existe qu'une
> fois la chaîne décodée. C'est voulu — l'oracle ne décode rien (v0 lexicale).

Une charge visant LLM07 ou LLM08 **documente** le risque ; elle ne le **mesure** pas, faute
d'artefact où la fuite serait observable (cf. §2).

---

## 4. Convention de citation (comment un texte cesse d'être une charge)

Le corpus contient des charges réelles ; les documents de sécurité en citent forcément.
L'oracle distingue **porter** une charge de la **citer** :

- **définition d'agent** — une charge à l'intérieur d'un bloc de code clôturé (```` ``` ````
  ou `~~~`), d'une citation (`>`) ou, pour un `agent.def` YAML, d'un commentaire `#`, est
  une **citation** (`INJ-3`, info). Le commentaire YAML est retenu parce que le parseur de
  `oracle-scan-agentdef.mjs` écarte explicitement ces lignes : elles ne peuplent aucun champ
  de l'agent ;
- **journal d'appels d'outils** — une charge dans une **sortie** d'outil (`output`) ou dans
  l'entrée d'un outil non agissant est une **ingestion** (`INJ-3`, info : c'est le cas
  normal d'une injection indirecte reçue puis ignorée). La même charge dans l'entrée d'un
  outil d'**action** (`Bash`, `PowerShell`, `Write`, `Edit`, `NotebookEdit`, `Agent`,
  `Task`, `SendMessage`, `mcp__*`) est une **traversée** (`INJ-2`, bloquant).

Cette convention est la raison d'être de la fixture *voisin légitime*
`fixtures/injection/vert-agentdef-defensif.md` : un agent anti-injection qui cite les mêmes
charges que la fixture rouge doit **passer**. C'est la mesure du faux positif, rejouée par
`oracles/self-test.mjs`.
