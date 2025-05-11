// .eslintrc.js
module.exports = {
  root: true,
  ignorePatterns: ['dist/', 'node_modules/', '.husky/'],

  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },

  env: {
    node: true,
    es2022: true,
    jest: true,
  },

  plugins: ['@typescript-eslint', 'import', 'prettier'],

  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:import/errors',
    'plugin:import/warnings',
    'plugin:import/typescript',
    'prettier',
  ],

  settings: {
    'import/resolver': {
      node: { extensions: ['.ts', '.js', '.json'] },
    },
  },

  rules: {
    'import/order': ['warn', { 'newlines-between': 'always' }],
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    'no-unused-vars': 'off',
    'prettier/prettier': 'error',
  },
};
