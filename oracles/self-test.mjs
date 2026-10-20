#!/usr/bin/env node
// self-test.mjs — preuve par le geste (double sens) : rejoue TOUTES les fixtures des deux
// oracles et vérifie que chaque verte PASSE et que chaque rouge ÉCHOUE pour la bonne raison
// (regle attendue présente dans les findings, pas juste un FAIL générique).
// Exit 0 si tous les contrôles passent, 1 sinon. À rejouer après toute modification.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FX = (...p) => path.join(HERE, "..", "fixtures", ...p);
const ORACLE_AGENTDEF = path.join(HERE, "oracle-scan-agentdef.mjs");
const ORACLE_TOOLCALLS = path.join(HERE, "oracle-scan-toolcalls.mjs");
const ORACLE_CORPUS = path.join(HERE, "oracle-corpus-injection.mjs");
const CORPUS = path.join(HERE, "..", "corpus", "injection-prompt.jsonl");

let pass = 0, echec = 0;
const ok = (b, m) => { console.log(`  [${b ? "PASS" : "FAIL"}] ${m}`); b ? pass++ : echec++; };

function runJson(script, args) {
  try { return JSON.parse(execFileSync(process.execPath, [script, ...args, "--json-only"], { encoding: "utf8" })); }
  catch (e) { try { return JSON.parse(String(e.stdout)); } catch { return { verdict: "ILLISIBLE", findings: [], _stderr: String(e.stderr || e) }; } }
}
function aRegle(res, regle) { return (res.findings || []).some((f) => f.regle === regle); }

console.log("SELF-TEST forge-agents-security — oracle-scan-agentdef (statique)\n");

// ── CAP-1 · combinaison de capacités dangereuse ──────────────────────────────
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "vert-lecture-seule.yaml")]);
  ok(r.verdict === "PASS", `vert-lecture-seule.yaml → PASS (obtenu ${r.verdict})`);
}
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "vert-lecture-ecriture.yaml")]);
  ok(r.verdict === "PASS", `vert-lecture-ecriture.yaml (Read+Write, pas de réseau) → PASS (obtenu ${r.verdict})`);
}
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "rouge-combo-dangereuse.yaml")]);
  ok(r.verdict === "FAIL" && aRegle(r, "CAP-1"), `rouge-combo-dangereuse.yaml (Read+Write+WebFetch) → FAIL avec CAP-1 (obtenu ${r.verdict})`);
}
{
  // D-49 (a) du 20/10/2026 : requalifiée — Bash seul passe, avec une note CAP-1 « mineur ».
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "vert-bash-seul.yaml")]);
  ok(r.verdict === "PASS" && aRegle(r, "CAP-1"), `vert-bash-seul.yaml (Bash seul, aucun outil réseau déclaré) → PASS avec une note CAP-1 (obtenu ${r.verdict})`);
}
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "rouge-bash-reseau.yaml")]);
  ok(r.verdict === "FAIL" && aRegle(r, "CAP-1"), `rouge-bash-reseau.yaml (Bash + WebFetch) → FAIL avec CAP-1 (obtenu ${r.verdict})`);
}

// ── CAP-2 · outil hors référentiel ───────────────────────────────────────────
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "rouge-outil-inconnu.yaml")]);
  ok(r.verdict === "FAIL" && aRegle(r, "CAP-2"), `rouge-outil-inconnu.yaml (SuperExfilTool) → FAIL avec CAP-2 (obtenu ${r.verdict})`);
}

// ── CAP-3 · permissions plus larges que le mandat ────────────────────────────
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "rouge-permissions-larges.yaml")]);
  ok(r.verdict === "FAIL" && aRegle(r, "CAP-3"), `rouge-permissions-larges.yaml (mandat lecture seule, outils Write/Edit) → FAIL avec CAP-3 (obtenu ${r.verdict})`);
}

// ── CAP-4 · motif d'exfiltration/injection dans le texte ────────────────────
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "rouge-prompt-exfiltration.yaml")]);
  ok(r.verdict === "FAIL" && aRegle(r, "CAP-4"), `rouge-prompt-exfiltration.yaml → FAIL avec CAP-4 (obtenu ${r.verdict})`);
}

// ── format subagent COMPILÉ (.claude/agents/<id>.md) ─────────────────────────
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "vert-compile.md")]);
  ok(r.verdict === "PASS", `vert-compile.md (subagent compilé, lecture seule) → PASS (obtenu ${r.verdict})`);
}
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "rouge-compile-combo.md")]);
  ok(r.verdict === "FAIL" && aRegle(r, "CAP-1") && aRegle(r, "CAP-4"),
    `rouge-compile-combo.md (subagent compilé, combo + curl|sh) → FAIL avec CAP-1 et CAP-4 (obtenu ${r.verdict})`);
}

// ── refus propre : cible absente ─────────────────────────────────────────────
{
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "n-existe-pas.yaml")]);
  ok(r.verdict === "SKIP", `cible introuvable → SKIP (obtenu ${r.verdict})`);
}

console.log("\nSELF-TEST forge-agents-security — oracle-scan-toolcalls (dynamique)\n");

const PERIMETRE = FX("toolcalls", "projet-demo");
const DOMAINES = FX("toolcalls", "domaines-autorisees.json");
const rt = (fichier, opts = {}) => runJson(ORACLE_TOOLCALLS, [
  FX("toolcalls", fichier), "--perimetre", opts.perimetre || PERIMETRE,
  ...(opts.domaines !== false ? ["--domaines", opts.domaines || DOMAINES] : []),
  ...(opts.seuils ? ["--seuils", FX("toolcalls", opts.seuils)] : []),
]);

// ── TC-1 · exfiltration réseau ───────────────────────────────────────────────
{ const r = rt("vert-reseau.jsonl"); ok(r.verdict === "PASS", `vert-reseau.jsonl (domaine autorisé, pas de pipe) → PASS (obtenu ${r.verdict})`); }
{ const r = rt("rouge-reseau-domaine.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-1"), `rouge-reseau-domaine.jsonl (domaine hors allowlist) → FAIL avec TC-1 (obtenu ${r.verdict})`); }
{ const r = rt("rouge-reseau-pipe.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-1"), `rouge-reseau-pipe.jsonl (curl | sh) → FAIL avec TC-1 (obtenu ${r.verdict})`); }

// ── TC-2 · destruction hors périmètre ────────────────────────────────────────
{ const r = rt("vert-destruction.jsonl"); ok(r.verdict === "PASS", `vert-destruction.jsonl (rm -rf dans le périmètre) → PASS (obtenu ${r.verdict})`); }
{ const r = rt("rouge-destruction.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-2"), `rouge-destruction.jsonl (rm -rf /) → FAIL avec TC-2 (obtenu ${r.verdict})`); }

// ── TC-3 · lecture de secrets ─────────────────────────────────────────────────
{ const r = rt("vert-secrets.jsonl"); ok(r.verdict === "PASS", `vert-secrets.jsonl (.env.example) → PASS (obtenu ${r.verdict})`); }
{ const r = rt("rouge-secrets.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-3"), `rouge-secrets.jsonl (.env) → FAIL avec TC-3 (obtenu ${r.verdict})`); }

// ── TC-4 · payload encodé anormalement long ──────────────────────────────────
{ const r = rt("vert-payload.jsonl"); ok(r.verdict === "PASS", `vert-payload.jsonl (base64 court) → PASS (obtenu ${r.verdict})`); }
{ const r = rt("rouge-payload.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-4"), `rouge-payload.jsonl (base64 de 120 caractères) → FAIL avec TC-4 (obtenu ${r.verdict})`); }

// ── TC-5 · écriture hors périmètre déclaré ───────────────────────────────────
{ const r = rt("vert-ecriture.jsonl"); ok(r.verdict === "PASS", `vert-ecriture.jsonl (écriture dans le périmètre) → PASS (obtenu ${r.verdict})`); }
{ const r = rt("rouge-ecriture.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-5"), `rouge-ecriture.jsonl (traversée hors périmètre) → FAIL avec TC-5 (obtenu ${r.verdict})`); }

// ── TC-6 · rafale d'appels non bornée (OWASP LLM10) ──────────────────────────
{ const r = rt("rouge-rafale.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-6"), `rouge-rafale.jsonl (25 appels Bash consécutifs, aucune borne) → FAIL avec TC-6 (obtenu ${r.verdict})`); }
// LÉGITIME VOISIN · même volume, mais lot déclaré ET tenu : le volume seul n'est pas un défaut
{
  const r = rt("vert-rafale-lot-borne.jsonl");
  const aucunDur = !(r.findings || []).some((f) => f.sev === "bloquant" || f.sev === "majeur");
  ok(r.verdict === "PASS" && aucunDur && aRegle(r, "TC-6"),
    `vert-rafale-lot-borne.jsonl (voisin légitime : 25 lectures d'un lot borné et tenu) → PASS, TC-6 en info seulement (obtenu ${r.verdict})`);
}
// La borne déclarée est VÉRIFIÉE, jamais crue : « lot_total: 3 » ne blanchit pas 25 appels
{ const r = rt("rouge-lot-depasse.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-6"), `rouge-lot-depasse.jsonl (lot_total=3 annoncé, 25 appels observés) → FAIL avec TC-6 (obtenu ${r.verdict})`); }

// ── TC-7 · entrée démesurée ──────────────────────────────────────────────────
{ const r = rt("vert-entree-normale.jsonl"); ok(r.verdict === "PASS", `vert-entree-normale.jsonl (volumétrie déclarée sous le seuil) → PASS (obtenu ${r.verdict})`); }
{ const r = rt("rouge-entree-demesuree.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-7"), `rouge-entree-demesuree.jsonl (50 Mio déclarés en entrée) → FAIL avec TC-7 (obtenu ${r.verdict})`); }

// ── TC-8 · boucle d'outil qui ne converge pas ────────────────────────────────
{ const r = rt("rouge-boucle.jsonl"); ok(r.verdict === "FAIL" && aRegle(r, "TC-8"), `rouge-boucle.jsonl (6 appels d'entrée strictement identique) → FAIL avec TC-8 (obtenu ${r.verdict})`); }
// LÉGITIME VOISIN · même outil, même nombre d'appels, mais l'entrée progresse
{
  const r = rt("vert-boucle-convergente.jsonl");
  ok(r.verdict === "PASS" && !aRegle(r, "TC-8"), `vert-boucle-convergente.jsonl (voisin légitime : 6 appels qui progressent) → PASS sans TC-8 (obtenu ${r.verdict})`);
}

// ── RÉTROCOMPATIBILITÉ · un journal v0 sans champ de volumétrie reste jugeable ─
{
  const r = rt("vert-reseau.jsonl");
  const aucunVolum = !aRegle(r, "TC-6") && !aRegle(r, "TC-7") && !aRegle(r, "TC-8");
  ok(r.verdict === "PASS" && aucunVolum, `vert-reseau.jsonl (format v0, aucun champ de volumétrie) → PASS sans TC-6/7/8 (obtenu ${r.verdict})`);
}
// Les seuils sont surchargeables — et un seuil invalide ne dégrade jamais en PASS
{ const r = rt("vert-boucle-convergente.jsonl", { seuils: "seuils-stricts.json" }); ok(r.verdict === "FAIL" && aRegle(r, "TC-6"), `--seuils strict (rafale_max 5) → la même rafale devient un défaut TC-6 (obtenu ${r.verdict})`); }
{ const r = rt("vert-reseau.jsonl", { seuils: "seuils-invalides.json" }); ok(r.verdict === "donnees_insuffisantes", `--seuils invalide (rafale_max 0) → donnees_insuffisantes, jamais PASS (obtenu ${r.verdict})`); }

// ── fail-closed : --perimetre obligatoire ────────────────────────────────────
{
  const r = runJson(ORACLE_TOOLCALLS, [FX("toolcalls", "vert-reseau.jsonl")]);
  ok(r.verdict === "donnees_insuffisantes", `sans --perimetre → donnees_insuffisantes, aucun défaut implicite (obtenu ${r.verdict})`);
}
// ── deny-by-default : sans --domaines, tout domaine externe est signalé ──────
{
  const r = rt("vert-reseau.jsonl", { domaines: false });
  ok(r.verdict === "FAIL" && aRegle(r, "TC-1"), `sans --domaines, allowlist vide → même un domaine « normal » est signalé (deny-by-default) (obtenu ${r.verdict})`);
}
// ── refus propre : journal absent ────────────────────────────────────────────
{
  const r = runJson(ORACLE_TOOLCALLS, [FX("toolcalls", "n-existe-pas.jsonl"), "--perimetre", PERIMETRE]);
  ok(r.verdict === "SKIP", `journal introuvable → SKIP (obtenu ${r.verdict})`);
}

console.log("\nSELF-TEST forge-agents-security — oracle-corpus-injection (rejeu du corpus LLM01)\n");

const FXI = (f) => FX("injection", f);
const rc = (fichier, opts = {}) => runJson(ORACLE_CORPUS, [
  FXI(fichier), "--corpus", opts.corpus || CORPUS, ...(opts.type ? ["--type", opts.type] : []),
]);

// ── intégrité du corpus lui-même (une charge mal formée doit se voir avant tout rejeu) ──
{
  const CHAMPS = ["id", "famille", "charge", "signature", "marqueur_effet", "effet_recherche", "categorie_owasp", "attendu", "severite"];
  let ok1 = true, motif = "";
  let charges = [];
  try {
    charges = fs.readFileSync(CORPUS, "utf8").split(/\r?\n/).filter((l) => l.trim()).map((l) => JSON.parse(l));
  } catch (e) { ok1 = false; motif = `corpus illisible : ${e.message}`; }
  if (ok1) {
    for (const c of charges) {
      const manquants = CHAMPS.filter((k) => c[k] === undefined);
      if (manquants.length) { ok1 = false; motif = `${c.id || "sans id"} : champs manquants [${manquants}]`; break; }
      try { new RegExp(c.signature, "i"); } catch (e) { ok1 = false; motif = `${c.id} : signature non compilable`; break; }
      if (!new RegExp(c.signature, "i").test(c.charge)) { ok1 = false; motif = `${c.id} : la signature ne reconnaît pas sa propre charge`; break; }
    }
    if (ok1 && new Set(charges.map((c) => c.id)).size !== charges.length) { ok1 = false; motif = "identifiants non uniques"; }
  }
  ok(ok1, `corpus : ${charges.length} charges bien formées, ids uniques, chaque signature reconnaît sa charge${ok1 ? "" : ` — ${motif}`}`);
  const d = charges.filter((c) => c.famille === "directe").length;
  const i = charges.filter((c) => c.famille === "indirecte").length;
  ok(d >= 10 && i >= 10, `corpus : les deux familles sont peuplées — ${d} directes / ${i} indirectes (≥ 10 chacune)`);
}

// ── INJ-1 · charge portée en clair par une définition d'agent ────────────────
{
  const r = rc("rouge-agentdef-charge.yaml");
  ok(r.verdict === "FAIL" && aRegle(r, "INJ-1"), `rouge-agentdef-charge.yaml (charge INJ-D-01 dans le mandat) → FAIL avec INJ-1 (obtenu ${r.verdict})`);
}
// ── LÉGITIME VOISIN · même charge, mais citée en bloc clôturé / citation ─────
{
  const r = rc("vert-agentdef-defensif.md");
  ok(r.verdict === "PASS" && aRegle(r, "INJ-3"), `vert-agentdef-defensif.md (voisin légitime : agent anti-injection qui CITE les mêmes charges) → PASS avec INJ-3, aucun faux positif (obtenu ${r.verdict})`);
}
{
  const r = rc("vert-agentdef-commentaire.yaml");
  ok(r.verdict === "PASS" && aRegle(r, "INJ-3"), `vert-agentdef-commentaire.yaml (charge en commentaire YAML, écarté par le parseur agent.def) → PASS avec INJ-3 (obtenu ${r.verdict})`);
}

// ── INJ-2 · traversée observée dans un journal ───────────────────────────────
{
  const r = rc("rouge-journal-traversee.jsonl");
  ok(r.verdict === "FAIL" && aRegle(r, "INJ-2"), `rouge-journal-traversee.jsonl (marqueur CANARI-I01 réémis dans un curl) → FAIL avec INJ-2 (obtenu ${r.verdict})`);
}
{
  const r = rc("rouge-journal-reemission.jsonl");
  ok(r.verdict === "FAIL" && aRegle(r, "INJ-2"), `rouge-journal-reemission.jsonl (texte de la charge INJ-I-04 réémis dans un Edit) → FAIL avec INJ-2 (obtenu ${r.verdict})`);
}
// ── INJ-3 · charge ingérée puis non suivie d'effet = comportement sain ───────
{
  const r = rc("vert-journal-injection-ignoree.jsonl");
  ok(r.verdict === "PASS" && aRegle(r, "INJ-3"), `vert-journal-injection-ignoree.jsonl (charge indirecte ingérée, jamais réémise) → PASS avec INJ-3 (obtenu ${r.verdict})`);
}
// ── LÉGITIME VOISIN · vocabulaire de sécurité qui ressemble à des charges ────
{
  const r = rc("vert-journal-voisin-legitime.jsonl");
  const aucunINJ = !aRegle(r, "INJ-1") && !aRegle(r, "INJ-2") && !aRegle(r, "INJ-3");
  ok(r.verdict === "PASS" && aucunINJ, `vert-journal-voisin-legitime.jsonl (charte anti-injection + « instructions … précédemment » : voisin légitime) → PASS sans aucun INJ-1/2/3 (obtenu ${r.verdict})`);
}
{
  const r = rc("vert-journal-propre.jsonl");
  const aucunINJ = !aRegle(r, "INJ-1") && !aRegle(r, "INJ-2") && !aRegle(r, "INJ-3");
  ok(r.verdict === "PASS" && aucunINJ, `vert-journal-propre.jsonl (journal banal, aucune charge) → PASS sans aucun INJ (obtenu ${r.verdict})`);
}

// ── fail-closed : jamais de PASS quand on ne peut pas juger ──────────────────
{
  const r = rc("n-existe-pas.jsonl");
  ok(r.verdict === "SKIP", `cible introuvable → SKIP, jamais PASS (obtenu ${r.verdict})`);
}
{
  const r = rc("format-inconnu.dat");
  ok(r.verdict === "SKIP", `format de cible inconnu → SKIP motivé, jamais PASS (obtenu ${r.verdict})`);
}
{
  const r = rc("skip-journal-illisible.jsonl");
  ok(r.verdict === "SKIP", `journal .jsonl sans aucune ligne JSON exploitable → SKIP, jamais PASS (obtenu ${r.verdict})`);
}
{
  const r = rc("vert-journal-propre.jsonl", { corpus: path.join(HERE, "..", "corpus", "n-existe-pas.jsonl") });
  ok(r.verdict === "donnees_insuffisantes", `corpus introuvable → donnees_insuffisantes, aucun rejeu réputé fait (obtenu ${r.verdict})`);
}

// ── TF-1319 · la découverte des oracles LIT LE DISQUE, dans les deux sens ─────────────────────
// Le juge du pilot (méta-oracle d'enclenchement) confronte ce que cette forge DÉCOUVRE aux
// verdicts consignés au ledger d'un run. Une découverte qui raterait un oracle le rendrait
// invisible au juge ; une découverte qui prendrait une recette ou une fixture pour un oracle
// ferait accuser un run de n'avoir pas joué ce qui n'est pas un oracle. Les deux sens se prouvent.
{
  const DECOUVRIR = path.join(HERE, "decouvrir-oracles.mjs");
  const decouvre = (racine) => {
    const r = spawnSync(process.execPath, [DECOUVRIR, ...(racine ? ["--racine", racine] : [])], { encoding: "utf8" });
    let j = null;
    try { j = JSON.parse(r.stdout); } catch { /* sortie illisible : les contrôles ci-dessous la disent */ }
    return { code: r.status, j };
  };
  const reel = decouvre(null);
  ok(reel.code === 0 && reel.j?.contrat === "digit-ai/decouverte-oracles@1" && reel.j?.forge === "digit-ai-forge-agents-security"
    && reel.j.oracles.length > 0 && reel.j.oracles.every((o) => fs.existsSync(path.join(HERE, "..", o.chemin))),
    `TF-1319 · VERT — la forge découvre ${reel.j?.oracles?.length ?? "?"} oracle(s) sur son propre disque, contrat digit-ai/decouverte-oracles@1 tenu, chaque chemin rendu existe`);
  const tmpDec = fs.mkdtempSync(path.join(os.tmpdir(), "forge-agents-security-decouverte-"));
  try {
    const poser = (rel) => {
      const p = path.join(tmpDec, rel);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, "// fixture de découverte\n");
    };
    ["oracles/oracle-alpha.mjs", "scripts/oracle_beta.py"].forEach(poser);
    const leurres = ["oracles/oracle-alpha.test.mjs", "oracles/self-test.mjs", "oracles/lib-oracle.mjs",
      "fixtures/oracle-faux.mjs", "Old/oracle-vieux.mjs", "node_modules/paquet/oracle-dep.mjs", "input/oracle-entrant.mjs"];
    leurres.forEach(poser);
    const v = decouvre(tmpDec);
    const noms = (v.j?.oracles || []).map((o) => o.nom).sort();
    ok(v.code === 0 && JSON.stringify(noms) === JSON.stringify(["oracle-alpha", "oracle_beta"]),
      `TF-1319 · VERT — un oracle posé sur le disque est découvert, où qu'il vive dans le dépôt (obtenu ${JSON.stringify(noms)})`);
    ok(v.code === 0 && !(v.j?.oracles || []).some((o) => leurres.includes(o.chemin)),
      `TF-1319 · ROUGE — recette, lanceur, bibliothèque, fixture, archive, dépendance et entrant ne sont JAMAIS pris pour des oracles (${leurres.length} leurres refusés)`);
    poser("oracles/oracle-gamma.mjs");
    const apres = decouvre(tmpDec);
    ok((apres.j?.oracles || []).some((o) => o.nom === "oracle-gamma" && o.chemin === "oracles/oracle-gamma.mjs"),
      "TF-1319 · un oracle AJOUTÉ est découvert au passage suivant sans qu'aucune liste soit tenue à jour : la liste vient du disque");
    poser("scripts/oracle-alpha.mjs");
    const doublon = decouvre(tmpDec);
    ok((doublon.j?.non_juge || []).some((n) => /oracle-alpha/.test(n) && /2 fichiers/.test(n)),
      "TF-1319 · deux fichiers du même nom sont DITS : un verdict qui le nomme ne dit pas lequel a tourné");
  } finally {
    fs.rmSync(tmpDec, { recursive: true, force: true });
  }
  const absente = decouvre(path.join(os.tmpdir(), "forge-agents-security-racine-qui-n-existe-pas"));
  ok(absente.code === 2 && absente.j?.oracles?.length === 0 && /introuvable/.test(absente.j?.motif || ""),
    `TF-1319 · ROUGE — une racine absente sort en 2 avec son motif, jamais en liste vide muette (obtenu exit ${absente.code})`);
}

console.log(`\nSelf-test forge-agents-security : ${pass} PASS, ${echec} FAIL`);
process.exit(echec ? 1 : 0);
