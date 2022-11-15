import click

from gift.compress.zip_manager import ZipManager
from gift.crypto.encryption_manager import EncryptionManager
from gift.gift import Gift
from gift.secrets.op_secrets_manager import OnePasswordSecretsManager


@click.group()
def cli() -> None:
    pass

@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--pwd-length', default=30, help='length of the password')
def wrap(filename: str, pwd_length: int) -> None:
    am = ZipManager()
    sm = OnePasswordSecretsManager()
    em = EncryptionManager(sm)
    gift = Gift(am, em)
    gift.wrap(filename=filename, pwd_length=pwd_length)

@cli.command()
@click.argument('filename', type=click.Path(exists=True, dir_okay=False))
@click.option('--outdir', '-o', default=".", type=click.Path(exists=True, file_okay=False))
def unwrap(filename: str, outdir: str) -> None:
    am = ZipManager()
    sm = OnePasswordSecretsManager()
    em = EncryptionManager(sm)
    gift = Gift(am, em)
    gift.unwrap(filename=filename, outdir=outdir)