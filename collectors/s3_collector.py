import boto3

from schemas.collector_output import CollectorOutput
from utils.aws_session import get_client, get_account_id, get_region
from utils.logger import get_logger

logger = get_logger(__name__)


def collect(session: boto3.Session) -> CollectorOutput:
    """
    [COL-02] Recopila configuración S3 relevante para auditoría CIS/WAF:
      - Lista de buckets
      - Block public access (cuenta + por bucket)
      - ACLs por bucket
      - Políticas de bucket
      - Versionado
      - Encriptación en reposo (SSE)
      - Logging de acceso
      - Replicación
      - Ciclo de vida
      - Object lock
      - Sitio web estático habilitado
    """
    s3         = get_client("s3", session)
    account_id = get_account_id(session)
    region     = get_region(session)
    errors: list[str] = []
    raw: dict = {}

    # ── 1. Block public access a nivel de cuenta ─────────────────────────────
    logger.info("S3: verificando block public access a nivel de cuenta")
    raw["account_public_access_block"] = None
    try:
        s3control = get_client("s3control", session)
        resp = s3control.get_public_access_block(AccountId=account_id)
        raw["account_public_access_block"] = resp["PublicAccessBlockConfiguration"]
    except Exception as e:
        errors.append(f"account_public_access_block: {e}")
        logger.error(f"S3: error obteniendo block public access de cuenta — {e}")

    # ── 2. Lista de buckets ───────────────────────────────────────────────────
    logger.info("S3: listando buckets")
    raw["buckets"] = {}
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        logger.info(f"S3: {len(buckets)} buckets encontrados")
    except Exception as e:
        errors.append(f"list_buckets: {e}")
        logger.error(f"S3: error listando buckets — {e}")
        buckets = []

    for bucket in buckets:
        name        = bucket["Name"]
        bucket_data = {
            "name":                  name,
            "creation_date":         bucket.get("CreationDate"),
            "region":                None,
            "public_access_block":   None,
            "acl":                   None,
            "policy":                None,
            "policy_status":         None,
            "versioning":            None,
            "encryption":            None,
            "logging":               None,
            "replication":           None,
            "lifecycle":             None,
            "object_lock":           None,
            "website":               None,
        }

        # Región del bucket
        try:
            loc = s3.get_bucket_location(Bucket=name)
            bucket_data["region"] = loc.get("LocationConstraint") or "us-east-1"
        except Exception as e:
            errors.append(f"bucket_location:{name}: {e}")

        # Block public access por bucket
        try:
            resp = s3.get_public_access_block(Bucket=name)
            bucket_data["public_access_block"] = resp["PublicAccessBlockConfiguration"]
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            bucket_data["public_access_block"] = {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        except Exception as e:
            errors.append(f"public_access_block:{name}: {e}")

        # ACL
        try:
            bucket_data["acl"] = s3.get_bucket_acl(Bucket=name)
        except Exception as e:
            errors.append(f"acl:{name}: {e}")

        # Política de bucket
        try:
            bucket_data["policy"] = s3.get_bucket_policy(Bucket=name).get("Policy")
        except Exception as e:
            err_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if err_code == "NoSuchBucketPolicy":
                bucket_data["policy"] = None
            else:
                errors.append(f"policy:{name}: {e}")

        # Estado público de la política
        try:
            bucket_data["policy_status"] = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus")
        except Exception:
            bucket_data["policy_status"] = None

        # Versionado
        try:
            bucket_data["versioning"] = s3.get_bucket_versioning(Bucket=name)
        except Exception as e:
            errors.append(f"versioning:{name}: {e}")

        # Encriptación SSE
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            bucket_data["encryption"] = enc.get("ServerSideEncryptionConfiguration")
        except Exception as e:
            err_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if err_code in ("ServerSideEncryptionConfigurationNotFoundError",
                            "ServerSideEncryptionConfigurationNotFound"):
                bucket_data["encryption"] = None
            else:
                errors.append(f"encryption:{name}: {e}")

        # Logging de acceso
        try:
            bucket_data["logging"] = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
        except Exception as e:
            errors.append(f"logging:{name}: {e}")

        # Replicación
        try:
            bucket_data["replication"] = s3.get_bucket_replication(Bucket=name).get("ReplicationConfiguration")
        except Exception as e:
            err_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if err_code == "ReplicationConfigurationNotFoundError":
                bucket_data["replication"] = None
            else:
                errors.append(f"replication:{name}: {e}")

        # Ciclo de vida
        try:
            bucket_data["lifecycle"] = s3.get_bucket_lifecycle_configuration(Bucket=name).get("Rules")
        except Exception as e:
            err_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if err_code == "NoSuchLifecycleConfiguration":
                bucket_data["lifecycle"] = None
            else:
                errors.append(f"lifecycle:{name}: {e}")

        # Object lock
        try:
            ol = s3.get_object_lock_configuration(Bucket=name)
            bucket_data["object_lock"] = ol.get("ObjectLockConfiguration")
        except Exception:
            bucket_data["object_lock"] = None

        # Sitio web estático
        try:
            bucket_data["website"] = s3.get_bucket_website(Bucket=name)
        except Exception:
            bucket_data["website"] = None

        raw["buckets"][name] = bucket_data

    # ── 3. Enrichments ────────────────────────────────────────────────────────
    logger.info("S3: calculando enrichments")
    _enrich(raw, errors)

    logger.info(
        f"S3: recolección completa — "
        f"{len(raw['buckets'])} buckets, "
        f"{len(errors)} errores"
    )

    return CollectorOutput(
        service="s3",
        account_id=account_id,
        region=region,
        raw_data=raw,
        errors=errors,
    )


def _enrich(raw: dict, errors: list[str]) -> None:
    """
    Calcula métricas derivadas por bucket:
      - is_public: ACL o política pública + block public access desactivado
      - encryption_type: AES256 | aws:kms | None
      - versioning_enabled: bool
      - logging_enabled: bool
      - has_lifecycle: bool
    """
    for name, bucket in raw.get("buckets", {}).items():
        try:
            # Encriptación
            enc = bucket.get("encryption")
            if enc:
                rules = enc.get("Rules", [])
                algo  = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") if rules else None
                bucket["encryption_type"] = algo
            else:
                bucket["encryption_type"] = None

            # Versionado
            ver = bucket.get("versioning") or {}
            bucket["versioning_enabled"] = ver.get("Status") == "Enabled"

            # Logging
            bucket["logging_enabled"] = bucket.get("logging") is not None

            # Lifecycle
            bucket["has_lifecycle"] = bool(bucket.get("lifecycle"))

            # Exposición pública
            pab = bucket.get("public_access_block") or {}
            all_blocked = all([
                pab.get("BlockPublicAcls", False),
                pab.get("IgnorePublicAcls", False),
                pab.get("BlockPublicPolicy", False),
                pab.get("RestrictPublicBuckets", False),
            ])

            policy_public = (bucket.get("policy_status") or {}).get("IsPublic", False)

            acl_public = False
            acl = bucket.get("acl") or {}
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in (
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ):
                    acl_public = True
                    break

            bucket["is_public"] = not all_blocked and (policy_public or acl_public)

        except Exception as e:
            errors.append(f"enrich:{name}: {e}")