import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import pluginImport from "eslint-plugin-import";
import configPrettier from "eslint-config-prettier";
import pluginJsonc from "eslint-plugin-jsonc";
import * as jsoncParser from "jsonc-eslint-parser";

export default tseslint.config(
  { ignores: ["coverage/**", "dist/**", "node_modules/**"] },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    languageOptions: {
      ecmaVersion: "latest",
      globals: { ...globals.node },
    },
    settings: {
      "import/resolver": {
        typescript: { project: "./tsconfig.eslint.json" },
      },
    },
  },

  {
    files: ["**/*.ts"],
    plugins: {
      import: pluginImport,
    },
    rules: {
      "padding-line-between-statements": [
        "error",
        { blankLine: "always", prev: "*", next: "return" },
        { blankLine: "always", prev: "import", next: "*" },
        { blankLine: "any", prev: "import", next: "import" },
        { blankLine: "always", prev: ["const", "let", "var"], next: "*" },
        { blankLine: "any", prev: ["const", "let", "var"], next: ["const", "let", "var"] },
        { blankLine: "always", prev: "*", next: ["class", "function", "export"] },
        { blankLine: "always", prev: ["block-like", "multiline-block-like"], next: "*" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-unused-vars": "off",
      "no-constant-condition": "error",
      "no-unreachable": "error",
      "import/no-extraneous-dependencies": [
        "error",
        {
          devDependencies: ["src/**/*.test.ts", "*.config.ts"],
        },
      ],
    },
  },

  ...pluginJsonc.configs["flat/recommended-with-jsonc"],
  {
    files: ["**/*.json", "**/*.jsonc"],
    languageOptions: {
      parser: jsoncParser,
    },
    rules: {
      "jsonc/sort-keys": ["error", { pathPattern: "^$", order: { type: "asc" } }],
    },
  },
  {
    files: ["package.json"],
    rules: {
      "jsonc/sort-keys": [
        "error",
        {
          pathPattern: "^$",
          order: [
            "name",
            "version",
            "private",
            "description",
            "author",
            "license",
            "engines",
            "type",
            "types",
            "main",
            "exports",
            "files",
            "sideEffects",
            "scripts",
            "peerDependencies",
            "dependencies",
            "devDependencies",
            "packageManager",
          ],
        },
        {
          pathPattern: "^(?:dev|peer|optional|bundled)?[Dd]ependencies$|^scripts$|^exports$",
          order: { type: "asc" },
        },
      ],
    },
  },

  configPrettier,
);
