const esbuild = require("esbuild");
const fs = require("fs");
const path = require("path");

async function build() {
  // Clean dist.
  fs.rmSync("dist", { recursive: true, force: true });
  fs.mkdirSync("dist", { recursive: true });

  // Bundle JS.
  const jsResult = await esbuild.build({
    entryPoints: ["src/main.ts"],
    bundle: true,
    outdir: "dist",
    minify: true,
    sourcemap: true,
    target: "es2020",
    entryNames: "[name]-[hash]",
    metafile: true,
  });

  // Bundle CSS.
  const cssResult = await esbuild.build({
    entryPoints: ["style.css"],
    bundle: true,
    outdir: "dist",
    minify: true,
    entryNames: "[name]-[hash]",
    metafile: true,
  });

  // Extract hashed filenames from metafiles.
  const jsFile = Object.keys(jsResult.metafile.outputs)
    .find((f) => f.endsWith(".js") && !f.endsWith(".map"));
  const cssFile = Object.keys(cssResult.metafile.outputs)
    .find((f) => f.endsWith(".css"));

  const jsName = path.basename(jsFile);
  const cssName = path.basename(cssFile);

  // Copy HTML files with updated asset references.
  for (const html of ["index.html", "receive.html"]) {
    let content = fs.readFileSync(html, "utf8");
    content = content.replace("app.js", jsName);
    content = content.replace("style.css", cssName);
    fs.writeFileSync(path.join("dist", html), content);
  }

  // Copy favicon.
  fs.copyFileSync("favicon.svg", path.join("dist", "favicon.svg"));

  console.log(`  ${jsName}`);
  console.log(`  ${cssName}`);
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
