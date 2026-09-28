# Build and maintain the documentation

This kit uses [Zensical](https://zensical.org/docs/) and the repository's existing
`.venv`. The source of each reference page remains the Markdown file in `docs/`.
Architecture and examples are maintained alongside those documents.

## Install the pinned Python environment

Run from the repository root. Reuse `.venv` if it already exists; create it only
when setting up a new checkout.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-docs.txt
.venv/bin/python -m pip check
```

`requirements-docs.in` names the direct dependency. `requirements-docs.txt` pins
Zensical and its installed dependency versions for repeatable installation. The
site uses the bundled Markdown, Pygments and PyMdown Extensions packages; no
separate MkDocs plugin stack is required. Python 3.14 is the environment used to
validate this kit.

## Preview

```sh
bash scripts/docs.sh serve
```

Open **http://127.0.0.1:8000/**. The preview process stays in the foreground;
stop it with Ctrl-C. It rebuilds when documentation changes. The equivalent direct
command is `.venv/bin/zensical serve`.

## Build

```sh
bash scripts/docs.sh build
```

The helper runs a clean, strict Zensical build. Build warnings fail the command.
The equivalent direct invocation is:

```sh
.venv/bin/zensical build --clean --strict
```

The output starts at `site-docs/index.html`. File-style URLs make page links usable
when inspecting the files directly, but use the preview server for browser search
and full theme/diagram behavior. This kit is not packaged as a completely offline
JavaScript application.

`site-docs/` is disposable generated output and is ignored by Git. It is separate
from `DATA/site/`, which contains issuer DID, status and discovery artifacts. A
documentation build reads `docs/` and explicit example snippets; it does not copy
runtime key, trust, status-registry or replay directories.

## Navigation and authoring

Edit `zensical.toml` to change navigation, palette, extensions or the output directory.
No production documentation URL is assumed. Set `project.site_url` to your actual
public documentation URL before deploying if canonical URLs and a sitemap are needed.

The small `docs-overrides/404.html` template gives the missing-page screen a valid
keyboard skip-link destination. Other pages use the bundled theme.

The kit provides search, a table of contents, code copying, light/dark palettes,
Mermaid diagrams and admonitions. System fonts avoid a remote font dependency.
The setup follows Zensical's [configuration](https://zensical.org/docs/setup/basics/)
and [native diagram](https://zensical.org/docs/authoring/diagrams/) guidance.

- Add a Markdown file under `docs/` and include it in the explicit navigation.
- Link to another page by source filename, for example `[Architecture](ARCHITECTURE.md)`.
- Use fenced `sh`, `json`, `toml`, `text` and `mermaid` blocks as appropriate.
- Keep examples consistent with the current CLI and `scripts/workflow.py`.
- The examples page includes the actual Holon and reveal JSON via PyMdown snippets,
  so those fixtures do not acquire a second manually maintained copy.
- Snippet paths resolve from the repository root and missing files fail the build.
  Include only intentional public examples; never include a runtime data directory.

## Updating packages

Change the desired Zensical version in `requirements-docs.in`, then update this
virtual environment and regenerate the resolved requirements:

```sh
.venv/bin/python -m pip install --upgrade -r requirements-docs.in
.venv/bin/python -m pip freeze > requirements-docs.txt
.venv/bin/python -m pip check
bash scripts/docs.sh build
```

Review dependency and generated-content changes before publishing. When command
behavior or crypto profiles change, also rerun the executable workflow and update
architecture, examples, CLI reference, standards and requirements pages together.

## Publish the kit

Copy the contents of `site-docs/` to your documentation web host after a successful
strict build. Serve HTML as `text/html`, CSS as `text/css`, and JavaScript with the
appropriate JavaScript content type. Keep its deployment separate from issuer
identity/status publication. This kit does not enable automatic remote deployment.
