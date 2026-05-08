import boto3
import botocore
from typing import Optional


def get_session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    """
    Retorna una sesión boto3 usando profile nombrado o credenciales del entorno.
    """
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region

    return boto3.Session(**kwargs)


def get_client(service: str, session: boto3.Session) -> botocore.client.BaseClient:
    """
    Retorna un cliente boto3 para el servicio indicado.
    """
    return session.client(service)


def get_account_id(session: boto3.Session) -> str:
    """
    Obtiene el account ID de la cuenta AWS activa.
    """
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


def get_region(session: boto3.Session) -> str:
    """
    Retorna la región configurada en la sesión.
    """
    return session.region_name or "us-east-1"