# gift 🎁

`gift` is a command line utility, written in Python, that can be used to "wrap" (compress and encrypt) and "unwrap" (decrypt and expand) files and directories. 

## Installation

The [1Password CLI](https://developer.1password.com) (version 2) is required (for now).

The package can be installed in editable mode by cloning this repo and running `pip install -e .`
To install dev dependencies (mypy, pytest, etc) as well run `pip install -e ".[dev]"`.

Alternatively, you can install the package with `pip install git+https://github.com/william-schor/gift`


## Usage

`gift` has two subcommands: `wrap` and `unwrap`.

### wrap
```
> gift wrap --help
Usage: gift wrap [OPTIONS] FILENAME

Options:
  --pwd-length INTEGER  length of the password
  --help                Show this message and exit.
```

### unwrap

```
Usage: gift unwrap [OPTIONS] FILENAME

Options:
  -o, --outdir DIRECTORY
  --help                  Show this message and exit.
```

## Secret Manager

One cool feature of `gift` is that it can use different secret managers to hold secret material. [1Password](https://1password.com) is the secret manager that inspired the project and is currently the only one implemented.

You should set up a vault in 1password for the tool to use! This keeps `gift`'s entries separate from yours. The default vault name is `FileWrap`. You can control
this via `settings.toml`. The best way to do that is to take the default `settings.toml` and install it in your home directory under `~/.gift/settings.toml`.
