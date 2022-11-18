import tomllib
from typing import Any, Type
import click
from pathlib import Path

###############
# compressors #
from gift.compress.archive_manager import ArchiveManager
from gift.compress.tar_manager import TarManager
from gift.compress.zip_manager import ZipManager
###############
##  crypto  ##
from gift.crypto.encryption_engine_builder import EncryptionEngineBuilder
from gift.crypto.formatters.encrypted_file_format import EncyptedFileFormatV1
from gift.crypto.engines.aes_cbc_encryption_engine import AesCbcEncryptionEngine
from gift.crypto.engines.encryption_engine import EncryptionEngine
###############
## secrets  ##
from gift.secrets.op_secrets_manager import OnePasswordSecretsManager
from gift.secrets.secrets_manager import SecretsManager
###############
##   Gift   ##
from gift.gift import Gift
###############

SETTINGS: dict[str, Any] | None = None
BLOCKS: dict[str, Any] | None = None


SECRET_MANAGERS: dict[str, Type[SecretsManager]] = {
    "1password": OnePasswordSecretsManager
}
ENCRYPTION_ENGINES: dict[str, Type[EncryptionEngine]] = {
    "aes-cbc": AesCbcEncryptionEngine
}
FILE_FORMATTERS: dict[str, Type[EncyptedFileFormatV1]] = {
    "v1": EncyptedFileFormatV1
}
ARCHIVE_MANAGERS: dict[str, Type[ArchiveManager]] = {
    "tar": TarManager,
    "zip": ZipManager
}

def load_settings() -> None:
    global SETTINGS
    global BLOCKS
    user_settings = (Path.home() / ".gift" / "settings.toml")
    if user_settings.exists():
        with open(user_settings, "rb") as f:
            SETTINGS = tomllib.load(f)
            BLOCKS = SETTINGS["building-blocks"]
    else:
        default_settings = Path(__file__).parent.parent.resolve()
        with open(default_settings / "settings.toml", "rb") as f:
            SETTINGS = tomllib.load(f)
            BLOCKS = SETTINGS["building-blocks"]



@click.version_option()
@click.group()
def cli() -> None:
    load_settings()


@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--secret-length', default=30, help='length of the secret (i.e. password)')
def wrap(filename: str, secret_length: int) -> None:
    if SETTINGS is None or BLOCKS is None:
        raise ValueError("Settings have not been set!")

    SelectedArchiveManager = ARCHIVE_MANAGERS[BLOCKS["archive-manager"]]
    am = SelectedArchiveManager()

    SelectedSecretManager = SECRET_MANAGERS[BLOCKS["secret-manager"]]
    # todo: build real abstractions here
    sm = SelectedSecretManager(SETTINGS["1password"]["vault"], SETTINGS["1password"]["command"])

    SelectedEncryptionEngine = ENCRYPTION_ENGINES[BLOCKS["encryption-engine"]]
    eb = EncryptionEngineBuilder(sm, SelectedEncryptionEngine, secret_length)

    SelectedFileManager = FILE_FORMATTERS[BLOCKS["file-format"]]
    ef = SelectedFileManager(eb, SETTINGS["v1"]["block-size"])

    gift = Gift(am, ef)
    gift.wrap(filename=filename)

@cli.command()
@click.argument('filename', type=click.Path(exists=True, dir_okay=False))
@click.option('--outdir', '-o', default=".", type=click.Path(exists=True, file_okay=False))
def unwrap(filename: str, outdir: str) -> None:
    if SETTINGS is None or BLOCKS is None:
        raise ValueError("Settings have not been set!")
    
    SelectedArchiveManager = ARCHIVE_MANAGERS[BLOCKS["archive-manager"]]
    am = SelectedArchiveManager()

    SelectedSecretManager = SECRET_MANAGERS[BLOCKS["secret-manager"]]
    sm = SelectedSecretManager(SETTINGS["1password"]["vault"], SETTINGS["1password"]["command"])

    SelectedEncryptionEngine = ENCRYPTION_ENGINES[BLOCKS["encryption-engine"]]
    eb = EncryptionEngineBuilder(sm, SelectedEncryptionEngine)

    SelectedFileManager = FILE_FORMATTERS[BLOCKS["file-format"]]
    ef = SelectedFileManager(eb, SETTINGS["v1"]["block-size"])

    gift = Gift(am, ef)
    gift.unwrap(filename=filename, outdir=outdir)