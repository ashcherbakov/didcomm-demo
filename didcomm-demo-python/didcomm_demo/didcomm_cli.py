import click
from peerdid.types import DIDDocVerMaterialFormat

from didcomm_demo.didcomm_demo import DIDCommDemo
from didcomm_demo.secrets.secrets_resolver_demo import SecretsResolverDemo

secrets_resolver = SecretsResolverDemo()


def set_secrets_resolver(resolver: SecretsResolverDemo):
    global secrets_resolver
    secrets_resolver = resolver


@click.group()
def cli():
    pass


@cli.command()
@click.option('--auth_keys_count', default=1, help='Number of authentication keys')
@click.option('--agreement_keys_count', default=0, help='Number of agreement keys')
@click.option('--service_endpoint', default=None, help='Optional service endpoint')
@click.option('--service_routing_keys', default=[], help='Optional service routing keys')
def create_peer_did(auth_keys_count, agreement_keys_count, service_endpoint, service_routing_keys):
    did = DIDCommDemo(secrets_resolver).create_peer_did(
        auth_keys_count=auth_keys_count,
        agreement_keys_count=agreement_keys_count,
        service_endpoint=service_endpoint,
        service_routing_keys=service_routing_keys
    )
    click.echo(f"{did}")


@cli.command()
@click.argument('did')
@click.option('--format', type=click.Choice(['jwk', 'multibase'], case_sensitive=False),
              default="jwk",
              help='DID Doc format (JWK or Multibase)')
def resolve_peer_did(did, format):
    format = DIDDocVerMaterialFormat.JWK if format == "jwk" else DIDDocVerMaterialFormat.MULTIBASE
    did_doc_json = DIDCommDemo.resolve_peer_did(did, format)
    click.echo(f"{did_doc_json}")


@cli.command()
def pack():
    pass


@cli.command()
def unpack():
    pass

# if __name__ == '__main__':
#     #cli()
#     private_key_jwk_dict, public_key_jwk_dict = generate_ed25519_key()
#     inception_key = jwk_x25519_to_peer_did_auth_key(public_key_jwk_dict)
#     did = peer_did.create_peer_did_numalgo_0(inception_key)
