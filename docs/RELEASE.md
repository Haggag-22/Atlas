# Releasing Atlas

This guide explains how to publish Atlas to PyPI so users get updates when they run `pipx upgrade atlas-redteam`.

---

## One-time setup: PyPI trusted publishing

For the GitHub Actions publish workflow to push to PyPI, you need to configure trusted publishing:

1. **Create a PyPI account** at [pypi.org](https://pypi.org) (if you don't have one).

2. **Create the project** on PyPI:
   - Go to [pypi.org/manage/projects/](https://pypi.org/manage/projects/)
   - Click "Add new project"
   - Name it `atlas-redteam`

3. **Add a trusted publisher**:
   - Open your `atlas-redteam` project on PyPI
   - Go to **Publishing** → **Add a new trusted publisher**
   - Choose **GitHub**
   - **Owner:** `Haggag-22`
   - **Repository:** `Atlas`
   - **Workflow name:** `publish.yml`
   - **Environment:** leave empty
   - Save

After this, the publish workflow can push to PyPI without storing any secrets.

---

## Release flow (for maintainers)

1. **Commit and push** your changes to `main`:
   ```bash
   git add .
   git commit -m "feat: add delete-case command"
   git push origin main
   ```

2. **GitHub Actions runs**:
   - **CI** — tests and lint
   - **Publish** — builds the package and publishes to PyPI (only if tests pass)

3. **Users get the update**:
   ```bash
   pipx upgrade atlas-redteam
   ```

---

## Versioning

Atlas uses [setuptools-scm](https://github.com/pypa/setuptools_scm) for versioning. The version is derived from git tags and commits:

- Tagged release (e.g. `v2.0.0`) → `2.0.0`
- Commits after a tag → `2.0.0a1.dev25` (dev version)

To release a stable version:

```bash
git tag v2.0.0
git push origin v2.0.0
```

The next push will publish `2.0.0` to PyPI.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Publish workflow fails with "403" | Trusted publishing not configured. Follow the one-time setup above. |
| "Version already exists" | That version was already published. Make a new commit to get a new dev version. |
| Users don't see new commands | They need to run `pipx upgrade atlas-redteam` to fetch the latest from PyPI. |
