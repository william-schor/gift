import click
from gift.secrets.op_secrets_manager import OnePasswordSecretsManager
from gift.compress.compression_manager import CompressionManager

@click.group()
def cli():
    pass

@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--pwd-length', default=20, help='length of the password')
def wrap(filename: str, pwd_length):
    opsm = OnePasswordSecretsManager()
    opsm.create_secret(filename, pwd_length)
    opsm.add_signature(filename, "here is a signature")
    print("Done!")

@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--destination', '-d', default=".", type=click.Path())
def unwrap(filename: str, destination: str):
    opsm = OnePasswordSecretsManager()
    print(opsm.read_secret(filename))
    print(opsm.read_signature(filename))