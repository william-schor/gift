import click
from gift.secrets.onepassword import OnePasswordSecretsManager
from gift.compress.compression_manager import CompressionManager

@click.group()
def cli():
    pass

@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--pwd-length', default=20, help='length of the password')
def wrap(filename: str, pwd_length):
    cm = CompressionManager()
    cm.wrap(filename)
    # opsm = OnePasswordSecretsManager()
    # print(opsm.create_secret(filename, pwd_length))

@cli.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--destination', '-d', default=".", type=click.Path())
def unwrap(filename: str, destination: str):
    cm = CompressionManager()
    cm.unwrap(filename, destination)
    # opsm = OnePasswordSecretsManager()
    # print(opsm.get_secret(filename))