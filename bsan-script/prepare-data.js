const fs = require('fs');
const path = require('path');

const ARTIFACTS_BASE_DIR = path.resolve(__dirname, '../artifacts');
const OUTPUT_DIR = path.resolve(__dirname, './dist');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'data.js');

const benchmarkData = {};

if (!fs.existsSync(ARTIFACTS_BASE_DIR)) {
  console.error(`Artifacts base directory not found: ${ARTIFACTS_BASE_DIR}`);
  process.exit(1);
}

// Read all subdirectories in ARTIFACTS_BASE_DIR (these are the architecture-specific result directories)
const architectureDirs = fs.readdirSync(ARTIFACTS_BASE_DIR, { withFileTypes: true })
  .filter(dirent => dirent.isDirectory())
  .map(dirent => dirent.name);

for (const archDirName of architectureDirs) {
  const archDirPath = path.join(ARTIFACTS_BASE_DIR, archDirName);
  benchmarkData[archDirName] = {};

  // Read all JSON files in the current architecture directory
  const benchmarkFiles = fs.readdirSync(archDirPath, { withFileTypes: true })
    .filter(dirent => dirent.isFile() && dirent.name.endsWith('.json'))
    .map(dirent => dirent.name);

  for (const benchmarkFileName of benchmarkFiles) {
    const benchmarkName = path.basename(benchmarkFileName, '.json');
    const benchmarkFilePath = path.join(archDirPath, benchmarkFileName);

    try {
      const fileContent = fs.readFileSync(benchmarkFilePath, 'utf8');
      if (fileContent.trim() === '') {
        console.warn(`Skipping empty file: ${archDirName}/${benchmarkFileName}`);
        continue;
      }
      benchmarkData[archDirName][benchmarkName] = JSON.parse(fileContent);
      console.log(`Successfully processed ${archDirName}/${benchmarkFileName}`);
    } catch (error) {
      console.error(`Error processing ${archDirName}/${benchmarkFileName}:`, error);
    }
  }
}

if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true }); // Ensure recursive creation
}

const outputContent = `window.benchmarkData = ${JSON.stringify(benchmarkData, null, 2)};`;
fs.writeFileSync(OUTPUT_FILE, outputContent);

console.log(`Benchmark data written to ${OUTPUT_FILE}`);
