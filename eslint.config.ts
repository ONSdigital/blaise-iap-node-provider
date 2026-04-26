import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import pluginImport from "eslint-plugin-import";
import pluginPrettier from "eslint-plugin-prettier";
import configPrettier from "eslint-config-prettier";

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
      prettier: pluginPrettier,
    },
    rules: {
      "no-trailing-spaces": "error",
      "eol-last": ["error", "always"],
      "no-multiple-empty-lines": ["error", { max: 1, maxEOF: 0, maxBOF: 0 }],
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
      "prettier/prettier": [
        "error",
        {
          singleQuote: false,
          semi: true,
          tabWidth: 2,
          useTabs: false,
          trailingComma: "all",
          printWidth: 100,
          bracketSpacing: true,
          arrowParens: "always",
          singleAttributePerLine: true,
          endOfLine: "lf",
        },
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

  configPrettier,
);
