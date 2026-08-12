#!/usr/bin/env node
// self-test.mjs — preuve par le geste (double sens) : rejoue TOUTES les fixtures des deux
// oracles et vérifie que chaque verte PASSE et que chaque rouge ÉCHOUE pour la bonne raison
// (regle attendue présente dans les findings, pas juste un FAIL générique).
// Exit 0 si tous les contrôles passent, 1 sinon. À rejouer après toute modification.
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FX = (...p) => path.join(HERE, "..", "fixtures", ...p);
const ORACLE_AGENTDEF = path.join(HERE, "oracle-scan-agentdef.mjs");
const ORACLE_TOOLCALLS = path.join(HERE, "oracle-scan-toolcalls.mjs");

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
  const r = runJson(ORACLE_AGENTDEF, [FX("agentdef", "rouge-bash-seul.yaml")]);
  ok(r.verdict === "FAIL" && aRegle(r, "CAP-1"), `rouge-bash-seul.yaml (Bash seul cumule les 3 capacités) → FAIL avec CAP-1 (obtenu ${r.verdict})`);
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

console.log(`\nSelf-test forge-agents-security : ${pass} PASS, ${echec} FAIL`);
process.exit(echec ? 1 : 0);
