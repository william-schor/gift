import click

###############
# compressors #
from gift.compress.tar_manager import TarManager
###############
##  crypto  ##
from gift.crypto.engines.encryption_engine_builder import EncryptionEngineBuilder
from gift.crypto.formatters.encrypted_file_format import EncyptedFileFormatV1

###############
## secrets  ##
from gift.secrets.op_secrets_manager import OnePasswordSecretsManager
from gift.secrets.passthrough_secrets_manager import PassthroughSecretsManager
###############
##   Gift   ##
from gift.gift import Gift
###############

@click.version_option()
@click.group()
def cli() -> None:
    pass


@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--secret-length', default=30, help='length of the secret (i.e. password)')
def wrap(filename: str, secret_length: int) -> None:
    am = TarManager()
    sm = PassthroughSecretsManager()
    eb = EncryptionEngineBuilder(sm, secret_length)
    ef = EncyptedFileFormatV1(eb)
    gift = Gift(am, ef)
    gift.wrap(filename=filename)

@cli.command()
@click.argument('filename', type=click.Path(exists=True, dir_okay=False))
@click.option('--outdir', '-o', default=".", type=click.Path(exists=True, file_okay=False))
def unwrap(filename: str, outdir: str) -> None:
    am = TarManager()
    sm = PassthroughSecretsManager()
    eb = EncryptionEngineBuilder(sm)
    ef = EncyptedFileFormatV1(eb)
    gift = Gift(am, ef)
    gift.unwrap(filename=filename, outdir=outdir)