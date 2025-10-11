# GitHub Actions CI/CD Setup

This repository includes GitHub Actions workflows for automated quality checks on every commit and pull request.

## Workflows

### Quality Checks (`quality-checks.yml`)

This workflow runs on every push and pull request to ensure code quality and translation completeness.

#### Jobs

1. **Translation Check**
   - Validates all translation files using the existing `validate-translations.js` script
   - Ensures all languages have the same keys
   - Reports missing or inconsistent translations
   - Fails the build if issues are found

2. **TODO Check**
   - Scans the codebase for TODO, FIXME, HACK, and XXX comments
   - Prevents commits with unresolved TODO items
   - Helps maintain clean, production-ready code

3. **Code Quality Summary**
   - Provides overall status of all quality checks
   - Comments on pull requests when checks fail

## Features

- **Automatic PR Comments**: Failed checks automatically comment on pull requests with details
- **Branch Protection**: Runs on both `main` and `develop` branches
- **Fast Execution**: Uses npm cache and efficient scripts
- **Comprehensive Scanning**: Checks relevant file types while excluding build artifacts

## Available Scripts

- `npm run validate` - Run translation validation (used by CI)
- `npm run fix` - Fix common translation issues
- `npm run check` - Validate with template generation
- `npm test` - Run validation (alias for validate)

## Workflow Triggers

The workflow triggers on:

- Push to `main` or `develop` branches
- Pull requests targeting `main` or `develop` branches

## File Exclusions

The TODO scanner excludes:

- `node_modules/`
- `.git/`
- `dist/` and `build/`
- `coverage/`
- Log files (`*.log`)

## Setup

No additional setup is required. The workflow uses the existing validation script and standard Node.js tools.

## Troubleshooting

### Translation Check Failures

- Run `npm run validate` locally to see detailed error messages
- Check that all language files have matching key structures
- Ensure JSON files are properly formatted

### TODO Check Failures

- Search for TODO comments in your code: `grep -r "TODO" .`
- Resolve or remove TODO items before committing
- Consider using issue tracking instead of code comments for larger tasks

## Local Development

You can run the same checks locally:

```bash
# Check translations
npm run validate

# Run tests (same as validate)
npm test
```

These commands will give you the same output as the CI pipeline, helping you catch issues before committing.

## Status Badges

Add this to your README.md:

```markdown
![Translation Check](https://github.com/axiorissocial/translations/actions/workflows/quality-checks.yml/badge.svg)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `npm test` locally
5. Ensure all checks pass
6. Submit a pull request

The automated checks will run on your PR and provide feedback if any issues are found.
