from pathlib import Path
from typing import NoReturn

import click

from gift.compress.compression_manager import CompressionManager
from gift.constants import FINAL_SUFFIX, UNWRAPPING_SUFFIX
from gift.crypto.encryption_manager import EncryptionManager
from gift.secrets.op_secrets_manager import OnePasswordSecretsManager
from gift.utils import tempdir, spinner


@click.group()
def cli() -> None:
    pass

@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--pwd-length', default=30, help='length of the password')
def wrap(filename: str, pwd_length: int) -> None:
    # temp dir is auto cleaned up
    with tempdir() as tmp_directory:
        # start by compressing the source
        with spinner(title="Compressing source files..."):
            cm = CompressionManager()
            intermediate_file = cm.wrap(filename, tmp_directory)
        click.echo("🗜️ Compressed! 🗜️")

        with spinner(title="Encrypting compressed archive..."):
            # now encrypt
            opsm = OnePasswordSecretsManager()
            em = EncryptionManager(opsm)
        
            with open(intermediate_file, 'rb') as source, open(f"{filename}{FINAL_SUFFIX}", 'wb') as sink:
                em.wrap(source, sink, pwd_length)

        click.echo("🔒 Encrypted! 🔒")

    click.echo(f"Created Wrapped File: {filename}{FINAL_SUFFIX}")
    click.echo("✅ Done! ✅")

@cli.command()
@click.argument('filename', type=click.Path(exists=True, dir_okay=False))
@click.option('--outdir', '-o', default=".", type=click.Path(exists=True, file_okay=False))
def unwrap(filename: str, outdir: str) -> None:
    if not filename.endswith(FINAL_SUFFIX):
        print("This is not a .wrapped file! Cannot proceed.")
        exit(-1)
        
    # temp dir is auto cleaned up
    with tempdir() as tmp_directory_path:
        tmp_directory = Path(tmp_directory_path)
        original_filename = filename.removesuffix(FINAL_SUFFIX)
        intermediate_file = tmp_directory / f"{original_filename}{UNWRAPPING_SUFFIX}"

        with spinner(title="Decrypting wrapped file..."):
            # decrypt
            opsm = OnePasswordSecretsManager()
            em = EncryptionManager(opsm)
            with (
                open(filename, 'rb') as source, 
                open(intermediate_file, 'wb') as sink
                ):
                used_password_id = em.unwrap(source, sink)
        click.echo("🔓 Decrypted! 🔓")
        
        with spinner(title="Expanding Archive..."): 
            unwrap_workspace = Path(outdir) / original_filename
            unwrap_workspace.mkdir()

            # decompress
            cm = CompressionManager()
            cm.unwrap(intermediate_file, unwrap_workspace)

        click.echo("📈 Expanded! 📈")

    # maybe clean up secret manager?
    if click.confirm('Do you want to remove the corresponding secret from your SecretManager?'):
        opsm.delete_secret(used_password_id)
        click.echo('🧹 Cleaned up secret! 🧹')
   
    click.echo(f"Created directory: {unwrap_workspace}") 
    click.echo("✅ Done! ✅")