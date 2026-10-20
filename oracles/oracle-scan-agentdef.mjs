#!/usr/bin/env node
// oracle-scan-agentdef — Domaine « Sécurité agentique : définition d'agent STATIQUE saine
// avant tout run » (déterministe, zéro dépendance, zéro exécution de l'agent scanné).
//
// Scanne un agent.def source (YAML, sous-ensemble documenté par forge-agents) ou un
// subagent COMPILÉ (`.claude/agents/<id>.md`, frontmatter + prompt) et rend un verdict sur
// quatre familles de défaut, figées au mandat TF-0111 :
//   CAP-1  combinaison de capacités dangereuse — réseau + écriture filesystem + lecture de
//          secrets cumulées par le même agent (surface d'exfiltration complète) ;
//   CAP-2  outil déclaré absent du référentiel fermé (data/referentiel-outils.json) —
//          supply-chain / typosquat / capacité hallucinée ;
//   CAP-3  permissions plus larges que ne l'exige le mandat déclaré (mandat de lecture/revue
//          mais outils d'écriture/exécution accordés) ;
//   CAP-4  texte de l'agent (mandat + corps) contenant un motif d'instruction d'exfiltration
//          ou d'injection ("envoie X vers http://...", "ignore les instructions...").
//
// Contrat JSON : { oracle, version, verdict, findings, non_juge }. Exit 0 (PASS) / 1 (FAIL) /
// 2 (SKIP — cible introuvable ou format illisible). Aucune exécution de l'agent scanné :
// analyse texte/structure uniquement (v0 statique, cf. README §Limites).
//
// Usage : node oracle-scan-agentdef.mjs <fichier.yaml|fichier.md> [--json-only]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = "0.2.0";
const ORACLE = "oracle-scan-agentdef";
const NON_JUGE = [
  "capacité réseau IMPLICITE d'un shell (Bash, PowerShell) sans outil réseau déclaré : notée « mineur », jamais bloquante depuis la 0.2.0 (D-49 (a) du 20/10/2026)",
  "exécution réelle de l'agent (v0 statique — ni sandbox ni interprétation du prompt par un modèle)",
  "analyse sémantique profonde du mandat au-delà de motifs lexicaux (heuristique, pas de compréhension)",
  "conformité du format à un substrat non Claude Code (façade queue git, etc.)",
  "existence réelle sur disque des artefacts déclarés en entrées/sorties",
  "légitimité métier d'un outil correctement déclaré et cohérent avec le mandat",
];

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REFERENTIEL = JSON.parse(fs.readFileSync(path.join(HERE, "data", "referentiel-outils.json"), "utf8"));

const args = process.argv.slice(2);
const cible = args.find((a) => !a.startsWith("--"));
const jsonOnly = args.includes("--json-only");
const F = [];
const add = (sev, regle, msg, where) => F.push({ sev, regle, msg, where });

function sortir(verdict, code) {
  process.stdout.write(JSON.stringify({
    oracle: ORACLE, version: VERSION, artefact: cible || null, verdict,
    findings: F.length ? F : [{ sev: "info", regle: "—", msg: "aucun défaut détecté sur les 4 familles CAP-1..4", where: cible }],
    non_juge: NON_JUGE,
  }, null, jsonOnly ? 0 : 2));
  process.exit(code);
}

if (!cible || !fs.existsSync(cible)) { add("info", "—", "cible introuvable", String(cible)); sortir("SKIP", 2); }
const brut = fs.readFileSync(cible, "utf8");

// ── Parseurs (sous-ensemble minimal, zéro dépendance, tolérant aux deux formats réels) ──

function stripQuotes(s) {
  s = s.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) return s.slice(1, -1);
  return s;
}
function parseInlineArray(s) {
  const inner = s.trim().replace(/^\[/, "").replace(/\]$/, "").trim();
  return inner === "" ? [] : inner.split(",").map((x) => stripQuotes(x));
}
function parseInlineObject(s) {
  const inner = s.trim().replace(/^\{/, "").replace(/\}$/, "").trim();
  const obj = {};
  for (const part of inner.split(",")) {
    const i = part.indexOf(":");
    if (i === -1) continue;
    obj[stripQuotes(part.slice(0, i))] = stripQuotes(part.slice(i + 1));
  }
  return obj;
}

// agent.def source (YAML, sous-ensemble forge-agents references/agent-def.md)
function parseAgentDefYaml(text) {
  const doc = {};
  let currentKey = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    if (/^[A-Za-z_][\w]*:/.test(line)) {
      const i = line.indexOf(":");
      const key = line.slice(0, i).trim();
      const val = line.slice(i + 1).trim();
      currentKey = key;
      if (val === "") doc[key] = [];
      else if (val.startsWith("[")) doc[key] = parseInlineArray(val);
      else if (val.startsWith("{")) doc[key] = parseInlineObject(val);
      else doc[key] = stripQuotes(val);
    } else if (/^\s+-\s+/.test(line)) {
      if (!currentKey || !Array.isArray(doc[currentKey])) continue;
      const item = line.replace(/^\s+-\s+/, "").trim();
      doc[currentKey].push(item.startsWith("{") ? parseInlineObject(item) : stripQuotes(item));
    }
  }
  return {
    id: doc.id || null,
    mandat: doc.mandat || "",
    outils: Array.isArray(doc.outils) ? doc.outils : [],
    corpsLibre: [doc.mandat, ...(doc.arbitre || [])].join("\n"),
    format: "agent.def",
  };
}

// subagent COMPILÉ Claude Code (.claude/agents/<id>.md : frontmatter + prompt)
function parseSubagentMd(text) {
  const m = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  const front = {};
  const body = m ? m[2] : text;
  if (m) {
    for (const raw of m[1].split(/\r?\n/)) {
      const i = raw.indexOf(":");
      if (i === -1) continue;
      const key = raw.slice(0, i).trim();
      const val = stripQuotes(raw.slice(i + 1).trim());
      front[key] = val;
    }
  }
  const outils = (front.tools || "").split(",").map((s) => s.trim()).filter(Boolean);
  return {
    id: front.name || null,
    mandat: front.description || "",
    outils,
    corpsLibre: [front.description || "", body].join("\n"),
    format: "subagent-compile",
  };
}

let def;
try {
  def = brut.trimStart().startsWith("---") ? parseSubagentMd(brut) : parseAgentDefYaml(brut);
} catch (e) {
  add("bloquant", "—", `fichier illisible par les deux parseurs (agent.def / subagent compilé) : ${e.message}`, cible);
  sortir("FAIL", 1);
}
if (!def.id && !def.outils.length && !def.mandat) {
  add("bloquant", "—", "aucun champ reconnu — ni agent.def ni subagent compilé valide", cible);
  sortir("FAIL", 1);
}

// ── CAP-1 · combinaison de capacités dangereuse (réseau + écriture + lecture secrets) ──
// 0.2.0 (D-49 (a) du 20/10/2026, TF-1935) — LE SHELL SEUL N'EST PLUS UNE COMBINAISON DANGEREUSE.
// En 0.1.0, Bash ou PowerShell comptait à la fois comme réseau, écriture et lecture : la porte
// rendait FAIL sur les 5 agents de la flotte du pilot sur 5, et sur 55 des 71 agents d'Everything
// Claude Code — elle ne distinguait plus un agent ordinaire d'un agent dangereux. Le réseau ne
// compte désormais que par un outil réseau DÉCLARÉ (WebFetch, WebSearch) : cumulé avec une
// écriture et une lecture (le shell peut les fournir), il reste bloquant. Un shell sans outil
// réseau déclaré laisse une note « mineur », non bloquante : sa capacité réseau implicite est
// dite, pas jugée (non_juge).
const CAT_RESEAU = ["WebFetch", "WebSearch"];
const SHELLS = ["Bash", "PowerShell"];
const CAT_ECRITURE = ["Write", "Edit", "NotebookEdit", ...SHELLS];
const CAT_LECTURE = ["Read", "Grep", ...SHELLS];
const outilsAgent = def.outils;
const match = (cat) => outilsAgent.filter((o) => cat.includes(o));
const mReseau = match(CAT_RESEAU), mEcriture = match(CAT_ECRITURE), mLecture = match(CAT_LECTURE), mShell = match(SHELLS);
if (mReseau.length && mEcriture.length && mLecture.length) {
  add("bloquant", "CAP-1",
    `combinaison de capacités dangereuse — réseau déclaré [${mReseau.join(",")}] + écriture [${mEcriture.join(",")}] + lecture [${mLecture.join(",")}] cumulées : surface d'exfiltration complète (lire un secret, l'exfiltrer, couvrir ses traces)`,
    "outils");
} else if (mShell.length) {
  add("mineur", "CAP-1",
    `shell [${mShell.join(",")}] sans outil réseau déclaré : sa capacité réseau implicite n'est pas jugée comme une combinaison dangereuse (D-49 (a) du 20/10/2026) — note, non bloquante`,
    "outils");
}

// ── CAP-2 · outil hors référentiel fermé ─────────────────────────────────────
const connus = new Set(REFERENTIEL.outils_connus);
const prefixes = REFERENTIEL.prefixes_connus || [];
for (const o of outilsAgent) {
  const ok = connus.has(o) || prefixes.some((p) => o.startsWith(p));
  if (!ok) add("majeur", "CAP-2", `outil « ${o} » absent du référentiel déclaré (data/referentiel-outils.json) — supply-chain, typosquat ou capacité hallucinée`, "outils");
}

// ── CAP-3 · permissions plus larges que le mandat déclaré ────────────────────
const MOTS_LECTURE_SEULE = /\b(audite|audit|revue|revoie|analyse|vérifie|verifie|contrôle|controle|évalue|evalue|inspecte|lecture seule|read[- ]only)\b/i;
const OUTILS_AU_DELA_LECTURE = ["Write", "Edit", "NotebookEdit", "Bash", "PowerShell", "Agent"];
if (MOTS_LECTURE_SEULE.test(def.mandat)) {
  const exces = outilsAgent.filter((o) => OUTILS_AU_DELA_LECTURE.includes(o));
  if (exces.length)
    add("majeur", "CAP-3", `mandat de lecture/revue (« ${def.mandat.slice(0, 80)}${def.mandat.length > 80 ? "…" : ""} ») mais outils excédant la lecture accordés : [${exces.join(", ")}] — moindre capacité non respectée`, "mandat/outils");
}

// ── CAP-4 · motif d'instruction d'exfiltration / injection dans le texte ─────
const MOTIFS_EXFIL = [
  { re: /(envoie|transmets|poste|publie|upload|copie|renvoie)[^.\n]{0,60}(https?:\/\/)/i, msg: "instruction d'envoi de données vers une URL" },
  { re: /exfiltr\w*/i, msg: "vocabulaire d'exfiltration explicite" },
  { re: /ignore\s+(les|toutes?\s+les)?\s*instructions?\s+(précédentes|precedentes|système|systeme|antérieures|anterieures)/i, msg: "motif d'injection de prompt (contournement des instructions précédentes)" },
  { re: /curl[^\n]{0,80}-d\s*@/i, msg: "envoi du contenu d'un fichier local en corps de requête réseau (curl -d @fichier)" },
  { re: /(base64\s*(-d|--decode|encode)?[^\n]{0,40})?(curl|wget)[^\n]{0,20}\|\s*(sh|bash|powershell|cmd)\b/i, msg: "téléchargement distant directement exécuté (pipe vers un interpréteur)" },
];
for (const { re, msg } of MOTIFS_EXFIL) {
  if (re.test(def.corpsLibre)) add("bloquant", "CAP-4", `motif suspect dans le texte de l'agent : ${msg}`, def.format === "subagent-compile" ? "description/corps" : "mandat/arbitre");
}

const durs = F.filter((f) => f.sev === "bloquant" || f.sev === "majeur");
sortir(durs.length ? "FAIL" : "PASS", durs.length ? 1 : 0);
