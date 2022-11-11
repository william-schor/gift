import click
from gift.secrets.onepassword import OnePasswordSecretsManager
@click.group()
def cli():
    pass

@cli.command()
@click.argument('filename')
@click.option('--pwd-length', default=20, help='length of the password')
def wrap(filename: str, pwd_length):
    opsm = OnePasswordSecretsManager()
    print(opsm.create_secret(filename, pwd_length))

@cli.command()
@click.argument('filename')
def unwrap(filename: str):
    opsm = OnePasswordSecretsManager()
    print(opsm.get_secret(filename))