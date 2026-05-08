import boto3

from schemas.collector_output import CollectorOutput
from utils.aws_session import get_client, get_account_id, get_region
from utils.logger import get_logger

logger = get_logger(__name__)


def collect(session: boto3.Session) -> CollectorOutput:
    """
    Recopila configuración IAM relevante para auditoría CIS/WAF:
      - Password policy
      - Credential report
      - Usuarios: MFA, access keys, políticas inline/adjuntas, grupos
      - Grupos: usuarios y políticas
      - Roles: trust policies, boundary policies
      - Customer managed policies con permisos excesivos
      - Virtual MFA en root
      - IAM Access Analyzer
      - SAML / OIDC identity providers
      - Instance profiles
      - Service Control Policies (si hay Organization)
    """
    iam        = get_client("iam", session)
    account_id = get_account_id(session)
    region     = get_region(session)
    errors: list[str] = []
    raw: dict = {}

    # ── 1. Password policy ───────────────────────────────────────────────────
    logger.info("IAM: recopilando password policy")
    try:
        raw["password_policy"] = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        raw["password_policy"] = None
        logger.warning("IAM: no existe password policy configurada")
    except Exception as e:
        errors.append(f"password_policy: {e}")
        logger.error(f"IAM: error obteniendo password policy — {e}")

    # ── 2. Credential report ─────────────────────────────────────────────────
    logger.info("IAM: generando credential report")
    try:
        while True:
            resp = iam.generate_credential_report()
            if resp["State"] == "COMPLETE":
                break

        report_resp = iam.get_credential_report()
        csv_content = report_resp["Content"].decode("utf-8")
        lines   = csv_content.strip().split("\n")
        headers = lines[0].split(",")

        raw["credential_report"] = []
        for line in lines[1:]:
            values = line.split(",")
            raw["credential_report"].append(dict(zip(headers, values)))

    except Exception as e:
        errors.append(f"credential_report: {e}")
        logger.error(f"IAM: error generando credential report — {e}")

    # ── 3. Virtual MFA en root ───────────────────────────────────────────────
    logger.info("IAM: verificando virtual MFA en root")
    raw["root_virtual_mfa"] = None
    try:
        resp = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")
        for device in resp["VirtualMFADevices"]:
            serial = device.get("SerialNumber", "")
            if ":mfa/root" in serial:
                raw["root_virtual_mfa"] = device
                break
    except Exception as e:
        errors.append(f"root_virtual_mfa: {e}")
        logger.error(f"IAM: error verificando MFA root — {e}")

    # ── 4. Usuarios: MFA, access keys, políticas, grupos ────────────────────
    logger.info("IAM: recopilando usuarios")
    raw["users"] = {}
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username  = user["UserName"]
                user_data = {
                    "user": user,
                    "mfa_devices": [],
                    "access_keys": [],
                    "attached_policies": [],
                    "inline_policies": [],
                    "groups": [],
                }

                try:
                    user_data["mfa_devices"] = iam.list_mfa_devices(UserName=username)["MFADevices"]
                except Exception as e:
                    errors.append(f"mfa_devices:{username}: {e}")

                try:
                    for key in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
                        key_detail = {"metadata": key}
                        try:
                            luk = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                            key_detail["last_used"] = luk.get("AccessKeyLastUsed", {})
                        except Exception:
                            pass
                        user_data["access_keys"].append(key_detail)
                except Exception as e:
                    errors.append(f"access_keys:{username}: {e}")

                try:
                    user_data["attached_policies"] = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
                except Exception as e:
                    errors.append(f"attached_policies:{username}: {e}")

                try:
                    user_data["inline_policies"] = iam.list_user_policies(UserName=username)["PolicyNames"]
                except Exception as e:
                    errors.append(f"inline_policies:{username}: {e}")

                try:
                    user_data["groups"] = iam.list_groups_for_user(UserName=username)["Groups"]
                except Exception as e:
                    errors.append(f"groups_for_user:{username}: {e}")

                raw["users"][username] = user_data

    except Exception as e:
        errors.append(f"list_users: {e}")
        logger.error(f"IAM: error listando usuarios — {e}")

    # ── 5. Grupos: usuarios y políticas ─────────────────────────────────────
    logger.info("IAM: recopilando grupos")
    raw["groups"] = {}
    try:
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for group in page["Groups"]:
                gname      = group["GroupName"]
                group_data = {
                    "group": group,
                    "users": [],
                    "attached_policies": [],
                    "inline_policies": [],
                }

                try:
                    group_data["users"] = iam.get_group(GroupName=gname)["Users"]
                except Exception as e:
                    errors.append(f"group_users:{gname}: {e}")

                try:
                    group_data["attached_policies"] = iam.list_attached_group_policies(GroupName=gname)["AttachedPolicies"]
                except Exception as e:
                    errors.append(f"group_attached_policies:{gname}: {e}")

                try:
                    group_data["inline_policies"] = iam.list_group_policies(GroupName=gname)["PolicyNames"]
                except Exception as e:
                    errors.append(f"group_inline_policies:{gname}: {e}")

                raw["groups"][gname] = group_data

    except Exception as e:
        errors.append(f"list_groups: {e}")
        logger.error(f"IAM: error listando grupos — {e}")

    # ── 6. Roles: trust policy, boundary, instance profiles ─────────────────
    logger.info("IAM: recopilando roles")
    raw["roles"] = {}
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                rname     = role["RoleName"]
                role_data = {
                    "role": role,
                    "trust_policy":       role.get("AssumeRolePolicyDocument", {}),
                    "boundary_policy":    role.get("PermissionsBoundary"),
                    "attached_policies":  [],
                    "inline_policies":    [],
                }

                try:
                    role_data["attached_policies"] = iam.list_attached_role_policies(RoleName=rname)["AttachedPolicies"]
                except Exception as e:
                    errors.append(f"role_attached_policies:{rname}: {e}")

                try:
                    role_data["inline_policies"] = iam.list_role_policies(RoleName=rname)["PolicyNames"]
                except Exception as e:
                    errors.append(f"role_inline_policies:{rname}: {e}")

                raw["roles"][rname] = role_data

    except Exception as e:
        errors.append(f"list_roles: {e}")
        logger.error(f"IAM: error listando roles — {e}")

    # ── 7. Instance profiles ─────────────────────────────────────────────────
    logger.info("IAM: recopilando instance profiles")
    raw["instance_profiles"] = {}
    try:
        paginator = iam.get_paginator("list_instance_profiles")
        for page in paginator.paginate():
            for profile in page["InstanceProfiles"]:
                pname = profile["InstanceProfileName"]
                raw["instance_profiles"][pname] = {
                    "profile": profile,
                    "roles":   [r["RoleName"] for r in profile.get("Roles", [])],
                }
    except Exception as e:
        errors.append(f"instance_profiles: {e}")
        logger.error(f"IAM: error listando instance profiles — {e}")

    # ── 8. Customer managed policies con permisos excesivos ──────────────────
    logger.info("IAM: analizando customer managed policies")
    raw["customer_policies"] = {}
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                pid   = policy["PolicyId"]
                pname = policy["PolicyName"]
                policy_data = {"policy": policy, "document": None, "has_star_star": False}

                try:
                    version_id = policy["DefaultVersionId"]
                    version    = iam.get_policy_version(PolicyArn=policy["Arn"], VersionId=version_id)
                    doc        = version["PolicyVersion"]["Document"]
                    policy_data["document"] = doc

                    # Detectar permisos *:* en cualquier statement
                    for stmt in doc.get("Statement", []):
                        actions   = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        if "*" in actions and "*" in resources and stmt.get("Effect") == "Allow":
                            policy_data["has_star_star"] = True
                            break

                except Exception as e:
                    errors.append(f"policy_document:{pname}: {e}")

                raw["customer_policies"][pname] = policy_data

    except Exception as e:
        errors.append(f"list_customer_policies: {e}")
        logger.error(f"IAM: error listando customer policies — {e}")

    # ── 9. IAM Access Analyzer ───────────────────────────────────────────────
    logger.info("IAM: verificando Access Analyzer")
    raw["access_analyzer"] = {"enabled": False, "analyzers": []}
    try:
        aa = get_client("accessanalyzer", session)
        resp = aa.list_analyzers()
        analyzers = resp.get("analyzers", [])
        raw["access_analyzer"]["analyzers"] = analyzers
        raw["access_analyzer"]["enabled"]   = any(
            a["status"] == "ACTIVE" for a in analyzers
        )
    except Exception as e:
        errors.append(f"access_analyzer: {e}")
        logger.error(f"IAM: error verificando Access Analyzer — {e}")

    # ── 10. SAML providers ───────────────────────────────────────────────────
    logger.info("IAM: recopilando SAML providers")
    raw["saml_providers"] = []
    try:
        resp = iam.list_saml_providers()
        raw["saml_providers"] = resp.get("SAMLProviderList", [])
    except Exception as e:
        errors.append(f"saml_providers: {e}")
        logger.error(f"IAM: error listando SAML providers — {e}")

    # ── 11. OIDC providers ───────────────────────────────────────────────────
    logger.info("IAM: recopilando OIDC providers")
    raw["oidc_providers"] = []
    try:
        resp = iam.list_open_id_connect_providers()
        raw["oidc_providers"] = resp.get("OpenIDConnectProviderList", [])
    except Exception as e:
        errors.append(f"oidc_providers: {e}")
        logger.error(f"IAM: error listando OIDC providers — {e}")

    # ── 12. Service Control Policies (Organizations) ─────────────────────────
    logger.info("IAM: verificando SCPs de Organizations")
    raw["scps"] = {"in_organization": False, "policies": []}
    try:
        org = get_client("organizations", session)
        org.describe_organization()
        raw["scps"]["in_organization"] = True

        paginator = org.get_paginator("list_policies")
        for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
            for scp in page["Policies"]:
                try:
                    detail = org.describe_policy(PolicyId=scp["Id"])
                    raw["scps"]["policies"].append(detail["Policy"])
                except Exception as e:
                    errors.append(f"scp_detail:{scp['Id']}: {e}")

    except org.exceptions.AWSOrganizationsNotInUseException:
        logger.info("IAM: cuenta no pertenece a una Organization")
    except Exception as e:
        errors.append(f"scps: {e}")
        logger.error(f"IAM: error verificando SCPs — {e}")

    # ── 13. Soporte — política AWSSupportAccess ──────────────────────────────
    logger.info("IAM: verificando acceso a soporte AWS")
    raw["support_role_exists"] = False
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="AWS"):
            for policy in page["Policies"]:
                if policy["PolicyName"] == "AWSSupportAccess":
                    raw["support_role_exists"] = True
                    break
            if raw["support_role_exists"]:
                break
    except Exception as e:
        errors.append(f"support_role: {e}")

    # ── 14. Enrichments: antigüedad de keys + inactividad de usuarios ─────────
    logger.info("IAM: calculando enrichments (antigüedad de keys, inactividad de usuarios)")
    try:
        _enrich(raw, errors)
    except Exception as e:
        errors.append(f"enrichments: {e}")
        logger.error(f"IAM: error en enrichments — {e}")

    orphaned = sum(1 for v in raw.get("user_activity", {}).values() if v.get("is_orphaned"))
    logger.info(
        f"IAM: recolección completa — "
        f"{len(raw.get('users', {}))} usuarios ({orphaned} huérfanos), "
        f"{len(raw.get('groups', {}))} grupos, "
        f"{len(raw.get('roles', {}))} roles, "
        f"{len(raw.get('customer_policies', {}))} políticas custom, "
        f"{len(errors)} errores"
    )

    return CollectorOutput(
        service="iam",
        account_id=account_id,
        region=region,
        raw_data=raw,
        errors=errors,
    )


def _enrich(raw: dict, errors: list[str]) -> None:
    """
    Calcula métricas derivadas sobre los datos ya recopilados:
      - Días de antigüedad de cada access key
      - Días desde último uso de cada access key
      - Días de inactividad por usuario (password + access keys)
      - Marca usuarios huérfanos (sin actividad en 90+ días)
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)

    def parse_date(value: str):
        """Parsea fechas ISO o 'N/A' del credential report."""
        if not value or value in ("N/A", "no_information", "not_supported"):
            return None
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None

    def days_since(dt) -> int | None:
        if dt is None:
            return None
        return (now - dt).days

    # ── Access key enrichments ────────────────────────────────────────────────
    for username, user_data in raw.get("users", {}).items():
        for key_detail in user_data.get("access_keys", []):
            meta = key_detail.get("metadata", {})

            create_date = meta.get("CreateDate")
            if hasattr(create_date, "tzinfo"):
                key_detail["age_days"] = days_since(
                    create_date if create_date.tzinfo else create_date.replace(tzinfo=timezone.utc)
                )
            else:
                key_detail["age_days"] = None

            last_used_date = key_detail.get("last_used", {}).get("LastUsedDate")
            if last_used_date and hasattr(last_used_date, "tzinfo"):
                key_detail["days_since_last_use"] = days_since(
                    last_used_date if last_used_date.tzinfo else last_used_date.replace(tzinfo=timezone.utc)
                )
            else:
                key_detail["days_since_last_use"] = None

    # ── User inactivity enrichments ───────────────────────────────────────────
    raw["user_activity"] = {}

    cred_map = {}
    for entry in raw.get("credential_report", []):
        cred_map[entry.get("user")] = entry

    for username, user_data in raw.get("users", {}).items():
        cred = cred_map.get(username, {})

        password_last_used = parse_date(cred.get("password_last_used"))
        password_enabled   = cred.get("password_enabled", "false").lower() == "true"

        # Último uso de cualquier access key activa
        key_last_used_dates = []
        for key_detail in user_data.get("access_keys", []):
            if key_detail.get("metadata", {}).get("Status") == "Active":
                lud = key_detail.get("last_used", {}).get("LastUsedDate")
                if lud and hasattr(lud, "tzinfo"):
                    key_last_used_dates.append(
                        lud if lud.tzinfo else lud.replace(tzinfo=timezone.utc)
                    )

        last_key_used = max(key_last_used_dates) if key_last_used_dates else None

        # Actividad más reciente entre password y access keys
        candidates = [d for d in [password_last_used, last_key_used] if d]
        last_activity = max(candidates) if candidates else None

        days_inactive = days_since(last_activity)

        raw["user_activity"][username] = {
            "password_enabled":        password_enabled,
            "password_last_used":      password_last_used.isoformat() if password_last_used else None,
            "last_key_used":           last_key_used.isoformat() if last_key_used else None,
            "last_activity":           last_activity.isoformat() if last_activity else None,
            "days_inactive":           days_inactive,
            "is_orphaned":             days_inactive is not None and days_inactive >= 90,
            "has_never_been_active":   last_activity is None,
        }