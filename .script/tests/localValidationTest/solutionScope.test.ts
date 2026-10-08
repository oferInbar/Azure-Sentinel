import { spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { expect } from "chai";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const validatorPath = path.join(repoRoot, ".script/local-validation/validate.js");

function validateJsonInPath(solutionPath: string) {
  return spawnSync("node", [validatorPath, "--path", solutionPath, "--only", "json", "--json"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

describe("local validation folder scope", () => {
  for (const solutionFolder of ["CiscoASA", "Endpoint Threat Protection Essentials"]) {
    it(`validates only current JSON files under Solutions/${solutionFolder}`, () => {
      const result = validateJsonInPath(path.join("Solutions", solutionFolder));
      expect(result.status, result.stderr).to.be.oneOf([0, 1]);

      const report = JSON.parse(result.stdout);
      expect(report.results.length).to.be.greaterThan(0);
      expect(report.results.every((entry: { filePath: string }) =>
        entry.filePath.startsWith(`Solutions/${solutionFolder}/`))).to.equal(true);
      if (solutionFolder === "CiscoASA") {
        expect(report.results.some((entry: { filePath: string }) =>
          entry.filePath === "Solutions/CiscoASA/Package/mainTemplate.json")).to.equal(true);
      }
    });
  }

  it("rejects a nonexistent explicit folder rather than validating another scope", () => {
    const result = validateJsonInPath("Solutions/this-solution-folder-does-not-exist");
    expect(result.status).to.equal(2);
    expect(result.stderr).to.contain("existing directory");
    expect(result.stdout).to.equal("");
  });

  it("does not treat a similarly prefixed solution as part of the requested folder", () => {
    const target = "Solutions/CiscoASA";
    const siblingFolders = fs.readdirSync(path.join(repoRoot, "Solutions"))
      .filter(name => name.startsWith("CiscoASA") && name !== "CiscoASA");
    const result = validateJsonInPath(target);
    expect(result.status, result.stderr).to.be.oneOf([0, 1]);

    const report = JSON.parse(result.stdout);
    for (const sibling of siblingFolders) {
      expect(report.results.some((entry: { filePath: string }) =>
        entry.filePath.startsWith(`Solutions/${sibling}/`))).to.equal(false);
    }
  });
});
