"""
The top level wrapper class for the module
"""
from pathlib import Path
import click

from gift.constants import FINAL_SUFFIX, UNWRAPPING_SUFFIX
from gift.compress.archive_manager import ArchiveManager
from gift.crypto.encryption_manager import EncryptionManager
from gift.utils import spinner, tempdir, warn


class Gift:
    def __init__(self, am: ArchiveManager, em: EncryptionManager) -> None:
        self.am = am
        self.em = em
    def wrap(
        self, 
        filename: str, 
        pwd_length: int, 
    ) -> None:
        # temp dir is auto cleaned up
        with tempdir() as tmp_directory:
            # start by compressing the source
            with spinner(title="Compressing source files..."):
                intermediate_file = self.am.wrap(filename, tmp_directory)
            click.echo("🗜️ Compressed! 🗜️")

            with spinner(title="Encrypting compressed archive..."):
                with open(intermediate_file, 'rb') as source, open(f"{filename}{FINAL_SUFFIX}", 'wb') as sink:
                    self.em.wrap(source, sink, pwd_length)

            click.echo("🔒 Encrypted! 🔒")

        click.echo(f"Created Wrapped File: {filename}{FINAL_SUFFIX}")
        click.echo("✅ Done! ✅")

    def unwrap(
        self, 
        filename: str, 
        outdir: str, 
    ) -> None:
        if not filename.endswith(FINAL_SUFFIX):
            print("This is not a .wrapped file! Cannot proceed.")
            exit(-1)
            
        # temp dir is auto cleaned up
        with tempdir() as tmp_directory_path:
            tmp_directory = Path(tmp_directory_path)
            original_filename = filename.removesuffix(FINAL_SUFFIX)
            intermediate_file = tmp_directory / f"{original_filename}{UNWRAPPING_SUFFIX}"

            with spinner(title="Decrypting wrapped file..."):
                with (
                    open(filename, 'rb') as source, 
                    open(intermediate_file, 'wb') as sink
                    ):
                    used_password_id = self.em.unwrap(source, sink)
            click.echo("🔓 Decrypted! 🔓")
            
            with spinner(title="Expanding Archive..."): 
                unwrap_workspace = Path(outdir) / original_filename
                unwrap_workspace.mkdir()

                # decompress
                self.am.unwrap(intermediate_file, unwrap_workspace)

            click.echo("📈 Expanded!  📈")
        
        if used_password_id:
            # maybe clean up secret manager?
            if click.confirm('Do you want to remove the corresponding secret from your SecretManager?'):
                self.em.secret_manager.delete_secret(used_password_id)
                click.echo('🧹 Cleaned up secret! 🧹')
        
        else:
            warn("⚠️  Warning! Unwrapping did not manage to record secret identifier...\n"
            "This could be a bug or you could be using a secret manager or"
            " encryption manager which does not support this behavior ⚠️")
        
        click.echo(f"Created directory: {unwrap_workspace}") 
        click.echo("✅ Done! ✅")
