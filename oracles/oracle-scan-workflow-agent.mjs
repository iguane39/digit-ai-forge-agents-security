#!/usr/bin/env node
// oracle-scan-workflow-agent — Domaine « Sécurité agentique : un agent lancé par un workflow GitHub
// Actions » (statique, déterministe, zéro dépendance, zéro réseau : lit des fichiers YAML, n'exécute
// rien, ne contacte jamais GitHub). TF-2002, étude du pilot du 28/10/2026, ligne G2.
//
// LE FAIT. Un produit du poste lance anthropics/claude-code-action depuis un workflow (mesure du pilot
// du 28/10/2026) ; les agents tiers de Copilot, dont Claude, sont en préversion. La forge jugeait les
// définitions d'agents et leurs journaux d'outils, jamais un agent lancé par Actions : qui peut le
// déclencher, quels secrets son shell lit, quel texte devient sa consigne.
//
// Sept règles sur les fichiers `.github/workflows/*.yml|*.yaml` d'un dépôt :
//   WA-1  déclencheur ouvert aux tiers : contrôle d'écriture de claude-code-action levé
//         (allowed_non_write_users, allowed_bots '*'), ou agent en ligne de commande lancé par un
//         événement de tiers sans filtre sur author_association ;
//   WA-2  texte d'un tiers (github.event.<…>.body, .title, github.head_ref…) interpolé dans la consigne
//         de l'agent (prompt, direct_prompt…) ou dans sa ligne de commande ;
//   WA-3  secret autre que ceux de l'agent posé dans l'environnement que son shell lit (env du
//         workflow, du job, de l'étape), ou show_full_output qui recopie tout au journal ;
//   WA-4  sous pull_request_target ou workflow_run, code de la pull request extrait à la racine de
//         l'espace de travail avant l'agent, qui y lit ses consignes et ses réglages ;
//   WA-5  outils sans borne : permissions contournées (--dangerously-skip-permissions, mode
//         bypassPermissions), ou shell libre et réseau accordés sur un déclencheur de tiers ;
//   WA-6  (info) id-token: write sur le job de l'agent — requis par l'action, à confronter aux
//         confiances fédérées du cloud ;
//   WA-7  job copilot-setup-steps de l'agent Copilot avec une permission d'écriture.
// Chaque règle cite sa page, lue le 29/10/2026 : oracles/data/referentiel-workflow-agent.json.
// Contrat : JSON {oracle, version, domaine, artefact, verdict, findings, sources, non_juge} · exit 0/1/2.
// Usage : node oracle-scan-workflow-agent.mjs <dépôt | dossier de workflows | fichier.yml> [--json-only]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { lireYaml } from "./lib-yaml.mjs";

const VERSION = "0.1.0";
const ORACLE = "oracle-scan-workflow-agent";
const DOMAINE = "securite-agentique/agent-dans-un-workflow";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const NON_JUGE = [
  "les agents de Copilot (agent cloud, agents tiers dont Claude) se règlent dans les réglages du compte ou de l'organisation, hors des fichiers lus : seul le job copilot-setup-steps est jugé (WA-7)",
  "les permissions du GITHUB_TOKEN en général, l'épinglage des actions par SHA, pull_request_target hors agent et l'injection dans un run: sans agent : WF-1 à WF-4 d'oracle-workflows de forge-websec",
  "les réglages du dépôt (actions autorisées, approbation des runs de forks, protections de branche) : ils vivent côté GitHub",
  "la configuration MCP passée à l'agent (--mcp-config) : les serveurs MCP se jugent par oracle-scan-mcp-supabase quand ils sont en fichier",
  "un secret écrit dans un fichier ou dans GITHUB_ENV par une étape antérieure : seul l'environnement déclaré est lu",
  "la confiance fédérée côté cloud (sujet OIDC) : WA-6 la rappelle, ne la lit pas",
  "un fichier que le lecteur YAML refuse (ancre, alias, étiquette) : dit non jugé, verdict FAIL, jamais un PASS silencieux",
  "les actions et commandes d'agent absentes du référentiel (anthropics/claude-code-base-action, autres agents) : non reconnues, donc non jugées — le référentiel s'étend quand leur documentation est lue",
  "les options de Copilot en ligne de commande au-delà de -p et --allow-tool, que la page lue le 29/10/2026 ne décrit pas",
];

const args = process.argv.slice(2);
const cible = args.find((a) => !a.startsWith("--"));
const jsonOnly = args.includes("--json-only");
const F = [];
let REF = null;
const add = (sev, regle, msg, where) => F.push({ sev, regle, msg, where, source: (REF?.sources || []).find((s) => s.regle === regle)?.url ?? null });

function sortir(verdict, code) {
  process.stdout.write(JSON.stringify({
    oracle: ORACLE, version: VERSION, domaine: DOMAINE, artefact: cible || null, verdict,
    findings: F.length ? F : [{ sev: "info", regle: "—", msg: "aucun agent lancé par ces workflows, ou aucun défaut sur WA-1..7", where: cible }],
    sources: (REF?.sources || []).map((s) => ({ regle: s.regle, url: s.url, lu_le: s.lu_le })),
    non_juge: NON_JUGE,
  }, null, jsonOnly ? 0 : 2));
  process.exit(code);
}

try { REF = JSON.parse(fs.readFileSync(path.join(HERE, "data", "referentiel-workflow-agent.json"), "utf8")); }
catch (e) { add("bloquant", "—", `référentiel data/referentiel-workflow-agent.json illisible (${String(e.message).slice(0, 80)}) : aucun agent ne serait reconnu, verdict refusé`, "oracles/data"); sortir("FAIL", 1); }

if (!cible || !fs.existsSync(cible)) { add("info", "—", "cible introuvable", String(cible)); sortir("SKIP", 2); }

// Les fichiers à lire : un fichier, un dossier de workflows, ou un dépôt qui porte .github/workflows.
const fichiers = [];
const st = fs.statSync(cible);
if (st.isFile()) fichiers.push(cible);
else {
  const dossier = fs.existsSync(path.join(cible, ".github", "workflows")) ? path.join(cible, ".github", "workflows") : cible;
  for (const nom of fs.readdirSync(dossier).sort()) if (/\.ya?ml$/i.test(nom)) fichiers.push(path.join(dossier, nom));
}
if (!fichiers.length) { add("info", "—", "aucun fichier de workflow (.yml, .yaml) à lire", String(cible)); sortir("SKIP", 2); }

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const texte = (v) => (v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
const RE_ACTIONS = (REF.actions_agent || []).map((a) => ({ ...a, re: new RegExp(a.motif, "i") }));
const RE_COMMANDES = (REF.commandes_agent || []).map((c) => ({ ...c, re: new RegExp(c.motif, "m") }));
const TIERS = new Set(REF.evenements_tiers || []);
const SECRETS_AGENT = new Set(REF.secrets_de_l_agent || []);
const FINS = (REF.contextes_non_fiables_fin || []).join("|");
// Une référence non fiable dans une expression ${{ … }} : github.event.<…>.<fin> ou github.head_ref.
const RE_NON_FIABLE = new RegExp(`\\$\\{\\{[^}]*\\b(github\\.event\\.[\\w.\\[\\]*'"-]*\\.(${FINS})|github\\.head_ref)\\b[^}]*\\}\\}`, "i");
const RE_SECRET = /\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g;

function declencheurs(on) {
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.map(String);
  if (estObjet(on)) return Object.keys(on);
  return [];
}
function permissionsEcriture(p) {
  if (p === "write-all") return ["write-all"];
  if (!estObjet(p)) return [];
  return Object.entries(p).filter(([, v]) => String(v).trim().toLowerCase() === "write").map(([k]) => k);
}
const idTokenEcriture = (p) => p === "write-all" || (estObjet(p) && String(p["id-token"] ?? "").trim().toLowerCase() === "write");
const filtreAuteur = (cond) => /author_association/.test(texte(cond)) && /\b(OWNER|MEMBER|COLLABORATOR)\b/.test(texte(cond));
const secretsDe = (env) => [...texte(env).matchAll(RE_SECRET)].map((m) => m[1]);

let agents = 0;
for (const f of fichiers) {
  const nomFichier = path.basename(f);
  let wf;
  try { wf = lireYaml(fs.readFileSync(f, "utf8")).valeur; }
  catch (e) { add("majeur", "—", `workflow non lu par le lecteur de l'oracle (${String(e.message).slice(0, 90)}${e.ligne ? `, ligne ${e.ligne}` : ""}) : non jugé, jamais un PASS silencieux`, nomFichier); continue; }
  if (!estObjet(wf) || !estObjet(wf.jobs)) continue;
  const evts = declencheurs(wf.on);
  const tiers = evts.filter((e) => TIERS.has(e));
  const pullTarget = evts.filter((e) => e === "pull_request_target" || e === "workflow_run");

  // WA-7 · le job de préparation de l'agent Copilot garde des permissions minimales.
  if (estObjet(wf.jobs["copilot-setup-steps"])) {
    agents++;
    const ecr = permissionsEcriture(wf.jobs["copilot-setup-steps"].permissions ?? wf.permissions);
    if (ecr.length) add("majeur", "WA-7", `${nomFichier} : job copilot-setup-steps avec une permission d'écriture [${ecr.join(", ")}] — « Set the permissions to the lowest permissions possible needed for your steps. » ; l'agent reçoit son propre jeton, ces droits ne servent qu'aux étapes de préparation (TF-2002)`, `${nomFichier} (job copilot-setup-steps)`);
  }

  for (const [idJob, job] of Object.entries(wf.jobs)) {
    if (!estObjet(job)) continue;
    const etapes = (Array.isArray(job.steps) ? job.steps : []).filter(estObjet);
    const ou = `${nomFichier} (job ${idJob})`;
    etapes.forEach((etape, rang) => {
      const uses = typeof etape.uses === "string" ? etape.uses : "";
      const run = typeof etape.run === "string" ? etape.run : "";
      const action = RE_ACTIONS.find((a) => a.re.test(uses));
      const commande = !action && run ? RE_COMMANDES.find((c) => c.re.test(run)) : null;
      if (!action && !commande) return;
      agents++;
      const qui = action ? action.agent : commande.agent;
      const avec = estObjet(etape.with) ? etape.with : {};
      const ouEtape = `${ou}, étape ${rang + 1}`;

      // WA-1 · qui peut lancer l'agent.
      if (action?.controle_ecriture_natif) {
        const nonEcrivains = texte(avec.allowed_non_write_users).trim();
        if (nonEcrivains === "*") add("bloquant", "WA-1", `${qui} : allowed_non_write_users: '*' — tout compte, sans droit d'écriture, lance l'agent ; l'option « bypasses the primary security mechanism of this action » (TF-2002)`, ouEtape);
        else if (nonEcrivains) add("majeur", "WA-1", `${qui} : allowed_non_write_users (${nonEcrivains.slice(0, 60)}) lève le contrôle d'écriture de l'action — « a significant security risk and should only be used for workflows with extremely limited permissions » (TF-2002)`, ouEtape);
        if (texte(avec.allowed_bots).trim() === "*" && tiers.length) add("bloquant", "WA-1", `${qui} : allowed_bots: '*' sur ${tiers.join(", ")} — « any such App can invoke this action with a prompt it controls » (TF-2002)`, ouEtape);
      } else if (tiers.length && !filtreAuteur(job.if) && !filtreAuteur(etape.if)) {
        add("bloquant", "WA-1", `${qui} lancé par ${tiers.join(", ")} sans filtre sur author_association (OWNER, MEMBER, COLLABORATOR) : aucune vérification d'auteur, tout compte qui peut ouvrir une issue ou commenter lance l'agent avec les droits du job (TF-2002)`, ouEtape);
      }

      // WA-2 · le texte d'un tiers devient la consigne.
      const consignes = (REF.entrees_de_consigne || []).filter((k) => RE_NON_FIABLE.test(texte(avec[k])));
      if (action && consignes.length) add("majeur", "WA-2", `${qui} : ${consignes.join(", ")} interpole un texte de tiers (github.event.<…>.body, .title, head_ref…) — ce texte devient la consigne de l'agent sans le nettoyage que l'action applique au contenu qu'elle lit elle-même (HTML commenté, caractères invisibles) ; le passer par une variable d'environnement et ne jamais en faire une instruction (TF-2002)`, ouEtape);
      if (commande && RE_NON_FIABLE.test(run)) add("bloquant", "WA-2", `${qui} : la ligne de commande de l'agent interpole un texte de tiers — injection dans le shell (« the expressions inside \${{ }} are evaluated and then substituted ») ET dans la consigne de l'agent (TF-2002)`, ouEtape);

      // WA-3 · les secrets que le shell de l'agent lit.
      const exposes = [
        ...secretsDe(wf.env).map((s) => [s, "env du workflow"]),
        ...secretsDe(job.env).map((s) => [s, "env du job"]),
        ...secretsDe(etape.env).map((s) => [s, "env de l'étape de l'agent"]),
        ...(action ? secretsDe(avec.settings).map((s) => [s, "settings de l'action"]) : []),
      ].filter(([s]) => !SECRETS_AGENT.has(s));
      for (const [s, ouSecret] of exposes) add("bloquant", "WA-3", `${qui} : secret ${s} posé dans l'${ouSecret} — le shell de l'agent lit son environnement, une consigne injectée peut l'en faire sortir ; claude-code-action ne nettoie l'environnement des sous-processus que si allowed_non_write_users est posé (« best-effort scrub », « reduces but does not eliminate prompt injection risk ») ; passer ce secret à la seule étape qui en a besoin, hors du job de l'agent (TF-2002)`, ouEtape);
      if (action && /^true$/i.test(texte(avec.show_full_output).trim())) add("majeur", "WA-3", `${qui} : show_full_output: true — « This outputs ALL Claude messages including tool execution results » au journal du run, public sur un dépôt public (TF-2002)`, ouEtape);

      // WA-4 · le code d'une pull request extrait à la racine, avant l'agent, sous les secrets du dépôt.
      if (pullTarget.length) {
        for (const avant of etapes.slice(0, rang)) {
          if (!/^actions\/checkout@/i.test(texte(avant.uses))) continue;
          const w = estObjet(avant.with) ? avant.with : {};
          const ref = texte(w.ref);
          const nonFiable = /github\.event\.pull_request\.head|github\.head_ref|github\.event\.workflow_run\.head/.test(ref);
          if (nonFiable && !texte(w.path).trim()) add("bloquant", "WA-4", `${qui} sous ${pullTarget.join(", ")} : actions/checkout extrait ${ref.trim()} à la racine de l'espace de travail AVANT l'agent — ces déclencheurs « execute with the base repository's secrets » et l'agent lit ses consignes et ses réglages dans l'espace de travail ; « Do not check out an untrusted ref into the workspace root before this action. » (TF-2002)`, ouEtape);
        }
      }

      // WA-5 · des outils sans borne.
      const outils = `${texte(avec.claude_args)}\n${texte(avec.settings)}\n${commande ? run : ""}`;
      if (/--dangerously-skip-permissions\b|--permission-mode[\s=]+["']?bypassPermissions\b|"defaultMode"\s*:\s*"bypassPermissions"/.test(outils))
        add("bloquant", "WA-5", `${qui} : contrôle des permissions de l'agent contourné (--dangerously-skip-permissions ou mode bypassPermissions) — chaque outil s'exécute sans règle (TF-2002)`, ouEtape);
      else if (tiers.length) {
        const listes = [...outils.matchAll(/--allowed-?tools[\s=]+["']?([^"'\n]+)/gi)].map((m) => m[1]);
        const autorises = listes.flatMap((l) => l.split(/[,\s]+/)).filter(Boolean);
        const libres = autorises.filter((o) => /^Bash(\(\*\))?$/.test(o) || /^(WebFetch|WebSearch)$/.test(o));
        if (/"allow"\s*:\s*\[[^\]]*"Bash"/.test(outils)) libres.push("Bash (settings)");
        // Copilot en ligne de commande : --allow-tool='shell' sans motif, là où la page montre shell(git show:*).
        if (/--allow-tool[\s=]+["']?shell(["'\s]|$)/m.test(outils)) libres.push("shell (--allow-tool)");
        if (libres.length) add("majeur", "WA-5", `${qui} lancé par ${tiers.join(", ")} avec des outils sans borne [${[...new Set(libres)].join(", ")}] — par défaut, « Claude has no shell or GitHub API access until you grant the tools the prompt needs » ; borner le shell à des commandes nommées (Bash(git status:*)) et retirer le réseau (TF-2002)`, ouEtape);
      }

      // WA-6 · (info) le jeton OIDC du job de l'agent.
      if (idTokenEcriture(job.permissions ?? wf.permissions))
        add("info", "WA-6", `${qui} : id-token: write sur le job de l'agent — requis par l'authentification de l'action, il permet aussi à son shell de demander un jeton OIDC ; une confiance fédérée du cloud qui accepte ce job (sujet de branche) lui ouvre le cloud : la lier à un environnement de production (O-21 de forge-ops) (TF-2002)`, ouEtape);
    });
  }
}

if (!agents) {
  const durs0 = F.filter((x) => x.sev === "bloquant" || x.sev === "majeur");
  if (!durs0.length) add("info", "—", `aucun agent lancé par ${fichiers.length} workflow(s) lu(s) (claude-code-action, Claude Code ou Copilot en ligne de commande) — rien à juger`, String(cible));
  sortir(durs0.length ? "FAIL" : "SKIP", durs0.length ? 1 : 2);
}
const durs = F.filter((x) => x.sev === "bloquant" || x.sev === "majeur");
sortir(durs.length ? "FAIL" : "PASS", durs.length ? 1 : 0);
