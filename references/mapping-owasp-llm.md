# Mapping des règles de la forge → OWASP Top 10 for LLM Applications

Rattache chaque règle **exécutée** de cette forge (`CAP-1..4`, `TC-1..8`, `INJ-1..3`, `WA-1..7`) aux
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
| `TC-6` | `oracle-scan-toolcalls` | rafale d'appels consécutifs au même outil **sans borne déclarée et tenue** (et borne annoncée non respectée) | **LLM10** | LLM06 |
| `TC-7` | `oracle-scan-toolcalls` | entrée d'un appel unique dépassant le seuil de volumétrie (champ déclaré, à défaut taille sérialisée) | **LLM10** | — |
| `TC-8` | `oracle-scan-toolcalls` | appels répétés d'entrée **strictement identique** — boucle d'outil sans progression | **LLM10** | LLM06 |
| `INJ-1` | `oracle-corpus-injection` | charge du corpus portée **en clair** par une définition d'agent | **LLM01** | LLM06 |
| `INJ-2` | `oracle-corpus-injection` | charge (ou son marqueur) retrouvée dans l'entrée d'un outil d'**action** — traversée | **LLM01** | LLM02, LLM05, LLM06 |
| `INJ-3` | `oracle-corpus-injection` | charge ingérée puis **non** réémise dans un acte — trace du comportement sain (info, jamais un défaut) | **LLM01** | — |
| `WA-1` | `oracle-scan-workflow-agent` | agent d'un workflow que des tiers peuvent déclencher (contrôle d'écriture levé, ou absent sans filtre d'auteur) | **LLM06** | LLM01 |
| `WA-2` | `oracle-scan-workflow-agent` | texte d'un tiers interpolé dans la consigne ou la ligne de commande de l'agent | **LLM01** | LLM06 |
| `WA-3` | `oracle-scan-workflow-agent` | secret posé dans l'environnement que lit le shell de l'agent ; sortie complète recopiée au journal | **LLM02** | LLM06 |
| `WA-4` | `oracle-scan-workflow-agent` | code d'une pull request extrait à la racine de l'espace de travail avant l'agent, sous les secrets du dépôt | **LLM01** | LLM02, LLM06 |
| `WA-5` | `oracle-scan-workflow-agent` | permissions de l'agent contournées, ou shell libre et réseau sur un déclencheur de tiers | **LLM06** | LLM02 |
| `WA-6` | `oracle-scan-workflow-agent` | `id-token: write` sur le job de l'agent (info, jamais un défaut) | **LLM06** | LLM02 |
| `WA-7` | `oracle-scan-workflow-agent` | job de préparation de l'agent Copilot avec une permission d'écriture | **LLM06** | — |

### Lecture inverse — catégorie → règles

| Catégorie | Règles qui la touchent | Niveau réel de couverture |
|---|---|---|
| **LLM01** Prompt Injection | CAP-4, TC-4, INJ-1, INJ-2, INJ-3, WA-2, WA-4 | **partielle, mesurée** — 34 charges du corpus rejouées sur artefact statique ; ni modèle vivant, ni reformulations hors corpus ; WA-2 et WA-4 ferment deux voies d'entrée d'un workflow (consigne interpolée, code de pull request lu) |
| **LLM02** Sensitive Information Disclosure | TC-1, TC-3, CAP-1, CAP-4, TC-4, INJ-2, WA-3 | **partielle** — chemins de secrets et sorties réseau observés ; secrets posés dans l'environnement d'un agent de workflow (WA-3) ; aucune détection de secret **dans le contenu** transmis (regex de chemin, pas de classifieur de donnée) |
| **LLM03** Supply Chain | CAP-2 | **marginale** — référentiel d'outils fermé uniquement ; ni provenance de modèle, ni intégrité de dépendance, ni signature de plugin/MCP |
| **LLM04** Data and Model Poisoning | TC-5 (effleuré), INJ-1 (effleuré) | **NON COUVERTE** — voir §2 |
| **LLM05** Improper Output Handling | TC-1 (pipe vers interpréteur), INJ-2 | **marginale** — un seul puits aval couvert (le shell) ; aucun contrôle d'assainissement vers HTML, SQL, rendu markdown, navigateur |
| **LLM06** Excessive Agency | CAP-1, CAP-2, CAP-3, TC-2, TC-5, INJ-2, TC-6/TC-8 (effleuré), WA-1, WA-5, WA-7 | **la mieux couverte** — surface déclarée (statique) + périmètre observé (dynamique) + agent de workflow (qui le déclenche, quels outils) ; reste hors champ : les actions à effet externe non journalisées |
| **LLM07** System Prompt Leakage | TC-3 (effleuré), charges INJ-D-03/D-04 (tentatives) | **NON COUVERTE** — voir §2 |
| **LLM08** Vector and Embedding Weaknesses | charge INJ-I-12 (tentative) | **NON COUVERTE** — voir §2 |
| **LLM09** Misinformation | charges INJ-I-06/I-12/I-17 (tentatives) | **NON COUVERTE** — voir §2 |
| **LLM10** Unbounded Consumption | TC-6, TC-7, TC-8 | **partielle, mesurée** — l'**absence de borne** est observée côté appels d'outils (rafale, entrée démesurée, boucle non convergente), sans aucun appel de modèle. Reste hors champ : jetons, coût monétaire, durée, et toute consommation côté modèle — voir §2 bis |

---

## 2. Catégories NON couvertes — déclaration nominale

Aucune règle de cette forge ne rend de verdict sur les catégories suivantes. Un run qui
passe tous ses oracles au vert **n'a rien dit** de ces cinq risques.

| Catégorie | Ce qui manque | Pourquoi, aujourd'hui |
|---|---|---|
| **LLM04** Data and Model Poisoning | aucun oracle n'inspecte un jeu d'entraînement, un jeu de fine-tuning, un index RAG ni une mémoire persistante | ces artefacts ne sont pas dans le périmètre v0 (définitions d'agents + journaux d'outils). `TC-5` détecte une écriture hors périmètre, pas l'empoisonnement d'un corpus dans le périmètre. Le corpus contient les charges INJ-D-14 et INJ-I-11 qui **tentent** l'empoisonnement — leur détection resterait une détection LLM01, pas une mesure LLM04 |
| **LLM05** Improper Output Handling | aucun contrôle de l'assainissement de la sortie du modèle avant son puits aval (HTML, SQL, shell, rendu markdown, navigateur) | seul le puits « shell » est effleuré par `TC-1` (pipe vers interpréteur). Les charges INJ-I-07 et INJ-I-08 (image et lien markdown exfiltrants) ciblent précisément ce trou : elles sont **écrites au corpus mais leur détection n'est possible que si l'artefact les trace** — le rendu côté client n'est pas journalisé |
| **LLM07** System Prompt Leakage | aucune règle ne compare une sortie au prompt système pour détecter une fuite | l'oracle statique ne connaît pas le prompt système effectif du harnais ; les journaux v0 ne portent pas les réponses en langage naturel. Les charges INJ-D-03 et INJ-D-04 sont au corpus comme **tentatives**, pas comme mesure de fuite |
| **LLM08** Vector and Embedding Weaknesses | aucun accès à un index vectoriel, aucune mesure de cloisonnement multi-locataire ni d'anomalie de récupération | aucun artefact de ce type n'entre dans les formats lus. La charge INJ-I-12 (document « aimant ») documente le risque sans le mesurer |
| **LLM09** Misinformation | aucune vérification factuelle des sorties | exigerait un jugement sémantique, donc un modèle : incompatible avec la contrainte « zéro API tierce payante, zéro budget » de cette forge. À porter par une autre forge (forge-tests / forge-data) si le besoin est mandaté |

**LLM03** figure au §1 comme « marginale » et non comme couverte : `CAP-2` ne vérifie qu'un
nom d'outil contre une liste tenue à la main. Ni provenance de modèle, ni intégrité de
dépendance, ni signature de serveur MCP ne sont contrôlées.

---

## 2 bis. LLM10 — ce qui est désormais mesuré, et où s'arrête la mesure (TF-0207)

LLM10 était la seule des catégories non couvertes atteignable **sans dépense** : la mesurer ne
demandait pas un modèle (contrairement à LLM09), seulement des **champs de volumétrie au
format de journal**. C'est fait — `TC-6`, `TC-7`, `TC-8`, et les champs optionnels
`taille_entree_octets` / `lot` / `lot_index` / `lot_total` documentés dans
`references/FORMAT-JOURNAL.md`.

**Le principe de la mesure** : ce qui est dénoncé n'est pas le **volume**, c'est l'**absence
de borne**. Un traitement par lot volumineux mais borné est légitime — le harnais déclare
`lot_total`, et l'oracle **vérifie que la borne tient** au lieu de la croire (sans quoi
`"lot_total": 1` blanchirait n'importe quelle rafale). La fixture *voisin légitime*
`fixtures/toolcalls/vert-rafale-lot-borne.jsonl` — 25 lectures d'un lot borné et respecté —
doit **passer**, et sa contre-épreuve `rouge-lot-depasse.jsonl` (borne annoncée à 3, 25 appels
observés) doit **échouer**. Les deux sont rejouées par `oracles/self-test.mjs`.

| Ce qui est mesuré | Ce qui ne l'est pas |
|---|---|
| rafale d'appels consécutifs au même outil sans borne tenue (`TC-6`) | **jetons**, **coût monétaire**, **durée de calcul** — le journal porte des appels d'*outils*, pas des appels de *modèle* |
| borne déclarée non tenue, incohérente ou dépassée (`TC-6`) | la **cadence** réelle : sans `ts`, 25 appels en une seconde et 25 appels en une journée sont indiscernables |
| taille d'entrée d'un appel unique (`TC-7`) | la taille **cumulée** d'une session, et la taille des **sorties** |
| boucle d'outil d'entrée strictement identique (`TC-8`) | une boucle qui **varie** son entrée sans progresser réellement (un compteur qui s'incrémente sans converger reste invisible) |
| — | la **légitimité métier** d'un lot : l'oracle vérifie que la borne annoncée est tenue, pas qu'elle est raisonnable |
| — | la consommation **côté modèle** : contexte qui enfle, réflexion sans fin, sur-appel d'un sous-agent non journalisé |

Autrement dit : LLM10 passe de « **non couverte** » à « **partielle, mesurée sur le versant
appels d'outils** ». Un run vert sur `TC-6..8` n'a rien dit du **coût** — seulement du fait
qu'aucune rafale, aucune entrée démesurée et aucune boucle stérile n'apparaît **dans le
journal fourni**.

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
| LLM10 | **aucune** — hors modèle de menace du corpus v0. LLM10 est mesurée par `TC-6..8` sur la **volumétrie du journal**, jamais par une charge du corpus (cf. §2 bis) |

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
