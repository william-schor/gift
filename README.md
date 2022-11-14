# gift 🎁

`gift` is a command line utility, written in Python, that can be used to "wrap" (compress and encrypt) and "unwrap" (decrypt and expand) files and directories. 

## Installation

TBA.

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
