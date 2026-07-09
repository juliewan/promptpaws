import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { inspectInput } from "../src/index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CORPUS_DIRS = [
  join(ROOT, "corpus/attacks"),
  join(ROOT, "corpus/benign"),
  join(ROOT, "corpus/known_gaps"),
];

interface CorpusCase {
  readonly text: string;
}

const cases = CORPUS_DIRS.flatMap((directory) =>
  readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .flatMap((name) =>
      JSON.parse(readFileSync(join(directory, name), "utf8")) as readonly CorpusCase[],
    ),
);

const pythonCode = `
import json, sys
from dataclasses import asdict
from promptpaws import inspect_input
out = []
for text in json.load(sys.stdin):
    verdict = inspect_input(text)
    out.append({
        "decision": verdict.decision.value,
        "risk_score": verdict.risk_score,
        "normalized_text": verdict.normalized_text,
        "signals": [asdict(signal) for signal in verdict.signals],
    })
json.dump(out, sys.stdout)
`;

const pythonResults = JSON.parse(
  execFileSync("python3", ["-c", pythonCode], {
    cwd: ROOT,
    env: { ...process.env, PYTHONPATH: join(ROOT, "src") },
    input: JSON.stringify(cases.map((entry) => entry.text)),
    encoding: "utf8",
  }),
) as readonly unknown[];

describe("Python parity across the shared corpus", () => {
  it.each(cases.map((entry, index) => [index, entry.text] as const))(
    "matches case %i: %s",
    (index, text) => {
      expect(inspectInput(text).toJSON()).toEqual(pythonResults[index]);
    },
  );
});
