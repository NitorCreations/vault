# nitor-vault

Python vault implementation.

See the [root readme](../README.md) for more information.

## Dependencies

The `requirements.txt` file is generated by pip-compile and should not be modified manually.
To update the requirements file, run:

```shell
pipx install pip-tools
pip-compile setup.py
```

## Code formatting and linting

Code formatting with [Black](https://github.com/psf/black).
Import sorting with [isort](https://github.com/PyCQA/isort).
Linting with [ruff](https://github.com/charliermarsh/ruff).

These are configured with a custom line length limit of 120.
The configs can be found in [pyproject.toml](./pyproject.toml).

Usage:

```shell
black .
isort .
ruff --fix .
```

These can also be integrated to IDEs / editors or run as a pre-commit hook.
See the documentation for Black [here](https://black.readthedocs.io/en/stable/integrations/editors.html).
Visual Studio Code has built-in support for
[Black](https://marketplace.visualstudio.com/items?itemName=ms-python.black-formatter)
and
[isort](https://marketplace.visualstudio.com/items?itemName=ms-python.isort)
through official plugins.
There is also a [Ruff extension](https://github.com/charliermarsh/ruff-vscode) for VS Code.

Using with [pre-commit](https://pre-commit.com/) (run from repo root):

```shell
# setup to be run automatically on git commit
pre-commit install

# run manually
pre-commit run --all-files
```
