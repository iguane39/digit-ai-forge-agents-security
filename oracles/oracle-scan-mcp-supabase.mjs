#!/usr/bin/env node
// oracle-scan-mcp-supabase — Domaine « Sécurité agentique : le serveur MCP de Supabase donné à un agent »
// (statique, déterministe, zéro dépendance, zéro réseau : lit des fichiers de configuration JSON, ne se
// connecte à aucun serveur). TF-2009, étude du pilot du 28/10/2026, ligne S4.
//
// LE FAIT. Supabase publie un serveur MCP officiel qui donne à un agent la main sur un projet : requêtes SQL,
// migrations, branches, fonctions. La forge jugeait les capacités et permissions des agents ; un serveur MCP
// de base de données n'y avait aucune règle — ni sa portée, ni son mode lecture seule, ni son projet.
//
// Cinq règles sur chaque entrée de serveur MCP de Supabase (hébergé mcp.supabase.com, local de la CLI sur
// le port 54321, ou paquet stdio @supabase/mcp-server-supabase) d'un fichier de configuration :
//   SB-1  portée : project_ref absent — l'agent atteint tous les projets du compte et ses outils de compte ;
//   SB-2  lecture seule : read_only=true absent — les requêtes s'exécutent avec un rôle qui écrit ;
//   SB-3  jamais la production : project_ref égal à un projet de production déclaré (--production) ;
//         sans déclaration (ni --production ni --aucune-production), le verdict n'est jamais PASS ;
//   SB-4  jeton en clair : en-tête Authorization, variable SUPABASE_ACCESS_TOKEN ou option qui porte une
//         valeur littérale, ou toute chaîne sbp_… du fichier ;
//   SB-5  groupes d'outils : features absent (tous les groupes sauf Storage sont actifs par défaut, Branching
//         compris) ou qui nomme branching — un agent peut créer une branche facturée.
// Le serveur local de la CLI sert la pile de développement : seule SB-4 s'y applique.
// Faits cités : oracles/data/referentiel-mcp-supabase.json, pages lues le 29/10/2026.
// Contrat : JSON {oracle, version, domaine, artefact, verdict, findings, sources, non_juge} · exit 0/1/2.
// Usage : node oracle-scan-mcp-supabase.mjs <fichier.json | dossier> [--production <ref>[,<ref>]] [--aucune-production "<motif>"] [--json-only]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = "0.1.0";
const ORACLE = "oracle-scan-mcp-supabase";
const DOMAINE = "securite-agentique/serveur-mcp-supabase";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const NON_JUGE = [
  "les serveurs MCP autres que celui de Supabase : non reconnus, donc non jugés",
  "la portée RÉELLE du jeton (organisations, projets, permissions choisis à sa création) : elle se lit dans le tableau de bord de Supabase, pas dans le fichier",
  "un project_ref résolu par une variable (${…}) : la règle « jamais la production » se joue dans l'environnement qui la résout — noté « mineur », jamais un PASS qui l'affirmerait",
  "la VÉRITÉ de la déclaration --production : un projet de production non déclaré passe SB-3",
  "l'approbation manuelle des appels d'outils dans le client MCP : un réglage du client, hors des fichiers lus",
  "la forme stdio du paquet @supabase/mcp-server-supabase : ses options --project-ref, --read-only et --features ne figurent pas sur la page officielle lue le 29/10/2026 ; elles sont lues telles que le paquet les nomme, non vérifiées ce jour",
  "une configuration MCP passée en ligne à un agent (--mcp-config '{…}' dans un workflow) : seuls les fichiers se lisent",
];

const args = process.argv.slice(2);
const jsonOnly = args.includes("--json-only");
const valeurDe = (opt) => { const i = args.indexOf(opt); return i >= 0 ? args[i + 1] : undefined; };
const avecValeur = new Set(["--production", "--aucune-production"]);
const cible = args.find((a, i) => !a.startsWith("--") && !avecValeur.has(args[i - 1]));
const production = new Set(args.flatMap((a, i) => (args[i - 1] === "--production" ? String(a).split(",") : [])).map((s) => s.trim().toLowerCase()).filter(Boolean));
const aucuneProduction = String(valeurDe("--aucune-production") ?? "").trim();
const F = [];
let REF = null;
const add = (sev, regle, msg, where) => F.push({ sev, regle, msg, where, source: (REF?.sources || []).find((s) => s.regle === regle)?.url ?? null });

function sortir(verdict, code) {
  process.stdout.write(JSON.stringify({
    oracle: ORACLE, version: VERSION, domaine: DOMAINE, artefact: cible || null, verdict,
    findings: F.length ? F : [{ sev: "info", regle: "—", msg: "aucun défaut sur SB-1..5", where: cible }],
    sources: (REF?.sources || []).map((s) => ({ regle: s.regle, url: s.url, lu_le: s.lu_le })),
    non_juge: NON_JUGE,
  }, null, jsonOnly ? 0 : 2));
  process.exit(code);
}

try { REF = JSON.parse(fs.readFileSync(path.join(HERE, "data", "referentiel-mcp-supabase.json"), "utf8")); }
catch (e) { add("bloquant", "—", `référentiel data/referentiel-mcp-supabase.json illisible (${String(e.message).slice(0, 80)}) : verdict refusé`, "oracles/data"); sortir("FAIL", 1); }
if (!cible || !fs.existsSync(cible)) { add("info", "—", "cible introuvable", String(cible)); sortir("SKIP", 2); }
if (valeurDe("--aucune-production") !== undefined && aucuneProduction.length < 10) {
  add("bloquant", "SB-3", "--aucune-production sans motif (10 caractères au moins) : le silence n'est pas une réponse", "--aucune-production");
  sortir("donnees_insuffisantes", 2);
}

const fichiers = fs.statSync(cible).isFile() ? [cible]
  : (REF.fichiers_de_configuration || []).map((r) => path.join(cible, ...r.split("/"))).filter((p) => fs.existsSync(p));
if (!fichiers.length) { add("info", "—", `aucun fichier de configuration MCP connu (${(REF.fichiers_de_configuration || []).join(", ")})`, String(cible)); sortir("SKIP", 2); }

// JSON, ou JSON à commentaires (configuration de VS Code) : commentaires et virgules finales retirés hors chaînes.
function lireJson(texte) {
  try { return JSON.parse(texte); } catch { /* essai JSONC ci-dessous */ }
  let out = "", q = false;
  for (let k = 0; k < texte.length; k++) {
    const c = texte[k];
    if (q) { out += c; if (c === "\\") { out += texte[++k] ?? ""; } else if (c === '"') q = false; continue; }
    if (c === '"') { q = true; out += c; continue; }
    if (c === "/" && texte[k + 1] === "/") { while (k < texte.length && texte[k] !== "\n") k++; out += "\n"; continue; }
    if (c === "/" && texte[k + 1] === "*") { k += 2; while (k < texte.length && !(texte[k] === "*" && texte[k + 1] === "/")) k++; k++; continue; }
    out += c;
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const variable = (v) => /\$\{[^}]+\}/.test(String(v));
// Paramètres d'une adresse, lus bruts (une variable ${…} y reste lisible).
function parametres(url) {
  const i = url.indexOf("?");
  const res = {};
  if (i < 0) return res;
  for (const paire of url.slice(i + 1).split("#")[0].split("&")) {
    const e = paire.indexOf("=");
    const cle = decodeURIComponent(e < 0 ? paire : paire.slice(0, e));
    res[cle] = e < 0 ? "" : decodeURIComponent(paire.slice(e + 1));
  }
  return res;
}
const hote = (url) => { const m = /^[a-z]+:\/\/([^/?#:]+)(?::(\d+))?([^?#]*)/i.exec(url); return m ? { nom: m[1].toLowerCase(), port: m[2] || "", chemin: m[3] || "" } : null; };
// Options d'une ligne de commande stdio : --cle=valeur, --cle valeur, --drapeau.
function options(argv) {
  const res = {};
  for (let k = 0; k < argv.length; k++) {
    const a = String(argv[k]);
    if (!a.startsWith("--")) continue;
    const e = a.indexOf("=");
    if (e > 0) res[a.slice(2, e)] = a.slice(e + 1);
    else if (k + 1 < argv.length && !String(argv[k + 1]).startsWith("-")) res[a.slice(2)] = String(argv[++k]);
    else res[a.slice(2)] = true;
  }
  return res;
}

let serveurs = 0, productionNonJugee = 0;
for (const f of fichiers) {
  const nomFichier = path.relative(fs.statSync(cible).isFile() ? path.dirname(cible) : cible, f).split(path.sep).join("/") || path.basename(f);
  const texte = fs.readFileSync(f, "utf8").replace(/^﻿/, "");
  // SB-4 · un jeton personnel en clair, où qu'il soit dans le fichier.
  const jetons = [...texte.matchAll(/\bsbp_[A-Za-z0-9]{8,}\b/g)].map((m) => m[0]);
  for (const j of new Set(jetons)) add("bloquant", "SB-4", `${nomFichier} : jeton personnel Supabase en clair (${j.slice(0, 8)}…) — « A token with full access carries every permission on every organization and project you belong to. » ; le retirer, le révoquer, et le passer par une variable d'environnement (\${SUPABASE_ACCESS_TOKEN}) (TF-2009)`, nomFichier);
  let doc;
  try { doc = lireJson(texte); }
  catch (e) { add("majeur", "—", `${nomFichier} : configuration illisible (${String(e.message).slice(0, 80)}) : non jugée, jamais un PASS silencieux`, nomFichier); continue; }
  const collections = [doc?.mcpServers, doc?.servers, doc?.mcp?.servers].filter(estObjet);
  for (const coll of collections) for (const [nom, s] of Object.entries(coll)) {
    if (!estObjet(s)) continue;
    const url = typeof s.url === "string" ? s.url : "";
    const argv = [s.command, ...(Array.isArray(s.args) ? s.args : [])].filter((x) => x !== undefined).map(String);
    const h = url ? hote(url) : null;
    const heberge = h?.nom === REF.hote_heberge;
    const local = !!h && ["localhost", "127.0.0.1", "[::1]"].includes(h.nom) && (REF.serveur_local_cli?.ports || []).includes(h.port) && h.chemin.replace(/\/$/, "") === REF.serveur_local_cli?.chemin;
    const stdio = argv.some((a) => a.includes(REF.paquet_stdio));
    if (!heberge && !local && !stdio) continue;
    serveurs++;
    const ou = `${nomFichier} (serveur ${nom})`;
    // SB-4 · l'en-tête, l'environnement et les options ne portent qu'une variable.
    const auth = estObjet(s.headers) ? Object.entries(s.headers).find(([k]) => k.toLowerCase() === "authorization")?.[1] : undefined;
    if (auth !== undefined && !variable(auth)) add("bloquant", "SB-4", `${ou} : en-tête Authorization à valeur littérale — l'exemple de la documentation passe \${SUPABASE_ACCESS_TOKEN}, jamais un jeton écrit dans le fichier (TF-2009)`, ou);
    const envJeton = estObjet(s.env) ? s.env.SUPABASE_ACCESS_TOKEN : undefined;
    if (envJeton !== undefined && String(envJeton).trim() && !variable(envJeton)) add("bloquant", "SB-4", `${ou} : SUPABASE_ACCESS_TOKEN à valeur littérale dans env — un jeton écrit dans un fichier de configuration se lit par quiconque lit le dépôt (TF-2009)`, ou);
    const opts = stdio ? options(argv) : {};
    if (typeof opts["access-token"] === "string" && !variable(opts["access-token"])) add("bloquant", "SB-4", `${ou} : --access-token à valeur littérale (TF-2009)`, ou);
    if (local) { add("info", "SB-1", `${ou} : serveur local de la CLI (pile de développement) — portée, lecture seule et production sans objet`, ou); continue; }

    const p = heberge ? parametres(url) : {};
    const ref = heberge ? p.project_ref : opts["project-ref"];
    const lectureSeule = heberge ? /^true$/i.test(String(p.read_only ?? "")) : opts["read-only"] === true || /^true$/i.test(String(opts["read-only"] ?? ""));
    const groupes = heberge ? p.features : opts.features;
    const forme = heberge ? "serveur hébergé" : "paquet stdio (options non vérifiées ce jour)";
    // SB-1 · la portée.
    if (ref === undefined || ref === true || !String(ref).trim())
      add("bloquant", "SB-1", `${ou}, ${forme} : aucun project_ref — l'agent atteint tous les projets du compte et les outils de compte (création de projet et de branche) ; « Scope your MCP server to a specific project, limiting access to only that project's resources. » ; ajouter ${heberge ? "?project_ref=<ref>" : "--project-ref=<ref>"} (TF-2009)`, ou);
    // SB-2 · la lecture seule.
    if (!lectureSeule)
      add("majeur", "SB-2", `${ou}, ${forme} : lecture seule absente — sans elle, les requêtes de l'agent écrivent ; read_only=true : « Execute all queries as a read-only Postgres user. » ; ajouter ${heberge ? "read_only=true" : "--read-only"} (TF-2009)`, ou);
    // SB-3 · jamais la production.
    if (typeof ref === "string" && ref.trim()) {
      if (variable(ref)) add("mineur", "SB-3", `${ou} : project_ref résolu par une variable (${ref}) — la règle « jamais la production » se joue dans l'environnement qui la résout`, ou);
      else if (production.has(ref.trim().toLowerCase())) add("bloquant", "SB-3", `${ou} : project_ref ${ref} est un projet de PRODUCTION déclaré — la règle de la Factory est plus stricte que la documentation (« Connect to a production project only when the task requires production evidence. ») : jamais la production dans une configuration d'agent ; viser un projet ou une branche de développement (TF-2009)`, ou);
      else if (!production.size && !aucuneProduction) productionNonJugee++;
    }
    // SB-5 · les groupes d'outils, et la dépense.
    const liste = typeof groupes === "string" ? groupes.split(",").map((g) => g.trim().toLowerCase()).filter(Boolean) : null;
    const depense = REF.groupe_depense;
    if (!liste) add("majeur", "SB-5", `${ou} : aucun features — « All groups except Storage are enabled by default. », Branching compris (« Note: Requires a paid plan. », 0,01344 $ l'heure par branche au plus petit calcul) : un agent peut créer une branche facturée, une dépense qui reste humaine (R-29) ; restreindre aux groupes nécessaires, par exemple features=database,docs (TF-2009)`, ou);
    else if (liste.includes(depense)) add("majeur", "SB-5", `${ou} : features nomme ${depense} — un agent peut créer une branche facturée (« Note: Requires a paid plan. ») : une dépense qui reste humaine (R-29) (TF-2009)`, ou);
  }
}

if (!serveurs) {
  const durs0 = F.filter((x) => x.sev === "bloquant" || x.sev === "majeur");
  if (!durs0.length) add("info", "—", `aucun serveur MCP de Supabase dans ${fichiers.length} fichier(s) lu(s) — rien à juger`, String(cible));
  sortir(durs0.length ? "FAIL" : "SKIP", durs0.length ? 1 : 2);
}
const durs = F.filter((x) => x.sev === "bloquant" || x.sev === "majeur");
if (durs.length) sortir("FAIL", 1);
if (productionNonJugee) {
  add("info", "SB-3", `${productionNonJugee} serveur(s) à project_ref littéral, et aucune production déclarée : passer --production <ref> (ou --aucune-production "<motif>") — sans elle, « jamais la production » n'est pas jugée et le verdict n'est pas rendu`, String(cible));
  sortir("donnees_insuffisantes", 2);
}
sortir("PASS", 0);
