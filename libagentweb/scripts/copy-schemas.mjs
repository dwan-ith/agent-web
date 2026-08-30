// Copy the packaged JSON artifacts next to the compiled entry point so the
// emitted dist/ tree is self-contained (the source imports them relatively).
import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = join(root, "typescript", "src", "schemas");
const target = join(root, "dist", "schemas");

mkdirSync(target, { recursive: true });
for (const entry of readdirSync(source)) {
  copyFileSync(join(source, entry), join(target, entry));
}
