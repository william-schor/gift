import click

###############
# compressors #
from gift.compress.tar_manager import TarManager
from gift.compress.zip_manager import ZipManager
from gift.compress.passthrough_archive_manager import PassthroughArchiveManager
###############
##  crypto  ##
from gift.crypto.aes_cbc_encryption_manager import AesCbcEncryptionManager
from gift.crypto.passthrough_encryption_manager import PassthroughEncryptionManager
###############
## secrets  ##
from gift.secrets.op_secrets_manager import OnePasswordSecretsManager
from gift.secrets.passthrough_secrets_manager import PassthroughSecretsManager
###############
##   Gift   ##
from gift.gift import Gift
###############


@click.group()
def cli() -> None:
    pass

@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--pwd-length', default=30, help='length of the password')
def wrap(filename: str, pwd_length: int) -> None:
    am = TarManager()
    sm = PassthroughSecretsManager()
    em = PassthroughEncryptionManager(sm)
    gift = Gift(am, em)
    gift.wrap(filename=filename, pwd_length=pwd_length)

@cli.command()
@click.argument('filename', type=click.Path(exists=True, dir_okay=False))
@click.option('--outdir', '-o', default=".", type=click.Path(exists=True, file_okay=False))
def unwrap(filename: str, outdir: str) -> None:
    am = TarManager()
    sm = PassthroughSecretsManager()
    em = PassthroughEncryptionManager(sm)
    gift = Gift(am, em)
    gift.unwrap(filename=filename, outdir=outdir)