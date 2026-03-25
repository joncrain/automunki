import base64
import json
import plistlib
import re
import uuid
from datetime import UTC, datetime

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.api.deps import get_session
from automunki.core.config import settings
from automunki.core.security import current_optional_user
from automunki.models.autopkg import (
    ApprovalStatus,
    AutoPkgMetadataCacheEntry,
    AutoPkgRecipe,
    AutoPkgRun,
    AutoPkgRunResult,
    GitHubRecipe,
    GitHubRecipeRepo,
    RecipeResultStatus,
    RunStatus,
    RunTriggerType,
    TrustChangeRequest,
    TrustStatus,
)
from automunki.models.munki import Catalog, PkgInfo, PkgInfoCatalog
from automunki.models.user import User
from automunki.schemas.autopkg import (
    ApprovalRequest,
    AutoPkgRecipeCreate,
    AutoPkgRecipeImportOverrideRequest,
    AutoPkgRecipeRead,
    AutoPkgRecipeUpdate,
    AutoPkgRunRead,
    GitHubCustomRepoAdd,
    GitHubRecipeRepoRead,
    MetadataCacheRead,
    MetadataCacheWrite,
    PkgInfoIngest,
    RunResultCreate,
    RunResultRead,
    TriggerRunRequest,
    TrustApprovalRequest,
    TrustChangeRequestRead,
    TrustCommitResolveRequest,
    TrustCommitResolveResponse,
)
from automunki.schemas.common import PaginatedResponse
from automunki.services.audit import create_audit_entry
from automunki.services.autopkg import (
    add_custom_repo_to_cache,
    discover_recipes_in_repo,
    dispatch_autopkg_workflow,
    normalize_github_full_name,
    remove_github_repo_from_cache,
    sync_all_recipes_to_cache,
    sync_repo_recipes_to_cache,
    sync_repos_to_cache,
)
from automunki.services.munki import sync_pkginfo_raw_plist
from automunki.services.trust import (
    GitHubRateLimitError,
    build_location_cache,
    build_override_data,
    compute_trust_info,
    fetch_recipe_content,
    infer_repos_from_trust_info,
    merge_db_trust_into_plist_for_runner,
    resolve_introducing_commit,
    trust_info_from_plist_parent_recipe_trust,
    verify_trust,
)

# Overrides with these trust states must not be dispatched to the runner.
TRUST_STATUS_BLOCKS_RUN = frozenset(
    {TrustStatus.failed.value, TrustStatus.pending_approval.value},
)


def _strip_pkginfo_from_input(input_dict: dict | None) -> dict | None:
    """Return a copy of Input without ``pkginfo`` (canonical pkginfo lives in override plist only)."""
    if not input_dict or "pkginfo" not in input_dict:
        return input_dict
    rest = {k: v for k, v in input_dict.items() if k != "pkginfo"}
    return rest if rest else None


def _normalize_pkginfo_into_override_only(recipe: AutoPkgRecipe) -> None:
    """
    When ``override_data`` is set, ``pkginfo`` must live only under ``override_data.Input``,
    not duplicated in ``input_variables``.
    """
    if not recipe.override_data:
        return
    iv = recipe.input_variables
    if not isinstance(iv, dict) or "pkginfo" not in iv:
        return
    pkg = iv["pkginfo"]
    rest = {k: v for k, v in iv.items() if k != "pkginfo"}
    recipe.input_variables = rest if rest else None
    od = dict(recipe.override_data)
    inp = dict(od.get("Input") or {})
    inp["pkginfo"] = pkg
    od["Input"] = inp
    recipe.override_data = od


def _runner_plist_dict_for_recipe(recipe: AutoPkgRecipe) -> dict:
    """
    Build the override plist dict passed to AutoPkg runners (same shape as
    ``overrides[].plist`` in ``GET /autopkg/runs/config``).
    """
    if recipe.override_data:
        plist = dict(recipe.override_data)
        trust = plist.get("ParentRecipeTrustInfo") or {}
        trust.setdefault("parent_recipes", {})
        trust.setdefault("non_core_processors", {})
        if trust:
            plist["ParentRecipeTrustInfo"] = trust
        merge_db_trust_into_plist_for_runner(plist, recipe.trust_info)
        iv = recipe.input_variables or {}
        inp = plist.get("Input")
        plist_input = dict(inp) if isinstance(inp, dict) else {}
        if "pkginfo" not in plist_input and isinstance(iv, dict) and iv.get("pkginfo") is not None:
            plist_input["pkginfo"] = iv["pkginfo"]
            plist["Input"] = plist_input
        return plist
    plist = {
        "Identifier": recipe.identifier,
        "ParentRecipe": recipe.parent_recipe or "",
        "Input": recipe.input_variables or {},
    }
    if recipe.trust_info:
        plist_trust: dict = {
            "parent_recipes": {},
            "non_core_processors": {},
        }
        for section in ("parent_recipes", "non_core_processors"):
            entries = recipe.trust_info.get(section, {})
            if entries:
                plist_trust[section] = {
                    k: {
                        "git_hash": "",
                        "sha256_hash": v.get("sha256_hash", ""),
                    }
                    for k, v in entries.items()
                }
        plist["ParentRecipeTrustInfo"] = plist_trust
    return plist


def _plist_trust_snippet_from_db_trust(trust_info: dict) -> dict:
    """Build ``ParentRecipeTrustInfo`` plist-shaped dict from canonical DB ``trust_info``."""
    plist_trust: dict = {
        "parent_recipes": {},
        "non_core_processors": {},
    }
    if trust_info.get("parent_recipes"):
        plist_trust["parent_recipes"] = {
            k: {"git_hash": "", "sha256_hash": v.get("sha256_hash", "")}
            for k, v in trust_info["parent_recipes"].items()
        }
    if trust_info.get("non_core_processors"):
        plist_trust["non_core_processors"] = {
            k: {"git_hash": "", "sha256_hash": v.get("sha256_hash", "")}
            for k, v in trust_info["non_core_processors"].items()
        }
    return plist_trust


def _parse_imported_override_content(raw: str) -> dict:
    """
    Parse an override from XML/binary plist, base64 binary plist, JSON object, or YAML.
    """
    s = raw.strip()
    if not s:
        raise HTTPException(status_code=400, detail="Empty content")

    if s.startswith("{"):
        try:
            d = json.loads(s)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}") from e
        if not isinstance(d, dict):
            raise HTTPException(status_code=400, detail="JSON must be an object")
        return d

    try:
        return plistlib.loads(s.encode("utf-8"))
    except Exception:
        pass

    try:
        b = base64.b64decode(s, validate=True)
        return plistlib.loads(b)
    except Exception:
        pass

    try:
        y = yaml.safe_load(s)
    except yaml.YAMLError:
        y = None
    if isinstance(y, dict):
        return y

    raise HTTPException(
        status_code=400,
        detail="Could not parse override (try XML plist, base64 binary plist, JSON object, or YAML)",
    )


router = APIRouter(prefix="/autopkg", tags=["autopkg"])


@router.post("/runs", response_model=AutoPkgRunRead)
async def trigger_run(
    data: TriggerRunRequest,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    if data.recipe_names:
        res = await session.execute(
            select(AutoPkgRecipe).where(AutoPkgRecipe.name.in_(data.recipe_names)),
        )
        found = {r.name: r for r in res.scalars().all()}
        missing = set(data.recipe_names) - set(found.keys())
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown recipe names: {', '.join(sorted(missing))}",
            )
        blocked = sorted(n for n, r in found.items() if r.trust_status in TRUST_STATUS_BLOCKS_RUN)
        if blocked:
            raise HTTPException(
                status_code=400,
                detail=(f"Cannot run recipes while trust is failed or pending approval: {', '.join(blocked)}"),
            )

    resolved_runner = data.runner if data.runner is not None else settings.autopkg_runner_mode
    if resolved_runner not in ("github", "local"):
        resolved_runner = "github"

    run = AutoPkgRun(
        status=RunStatus.pending,
        trigger_type=RunTriggerType.manual_ui,
        triggered_by=user.email if user else "anonymous",
        recipe_filter=data.recipe_names,
        runner_type=resolved_runner,
    )
    session.add(run)
    await session.flush()

    if resolved_runner == "local":
        result: dict = {"status": "local_pending"}
    else:
        result = await dispatch_autopkg_workflow(
            run_id=str(run.id),
            recipe_names=data.recipe_names,
        )

    if "error" in result:
        run.status = RunStatus.failed
        run.error_message = result["error"]
    elif result.get("status") == "local_pending":
        run.status = RunStatus.pending
        run.error_message = None
    else:
        run.status = RunStatus.running
        run.started_at = datetime.now(UTC)

    await create_audit_entry(
        session,
        action="trigger_run",
        entity_type="autopkg_run",
        entity_id=str(run.id),
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        after_snapshot={"recipe_filter": data.recipe_names},
    )

    await session.commit()
    await session.refresh(run)
    return AutoPkgRunRead.model_validate(run)


@router.get("/runs", response_model=PaginatedResponse)
async def list_runs(
    session: AsyncSession = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    count = (await session.execute(select(func.count()).select_from(AutoPkgRun))).scalar() or 0

    result = await session.execute(
        select(AutoPkgRun)
        .options(selectinload(AutoPkgRun.results))
        .order_by(AutoPkgRun.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    runs = result.scalars().unique().all()

    return PaginatedResponse(
        items=[AutoPkgRunRead.model_validate(r) for r in runs],
        total=count,
        page=page,
        page_size=page_size,
        total_pages=(count + page_size - 1) // page_size,
    )


@router.post("/runs/claim-next-local", response_model=AutoPkgRunRead)
async def claim_next_local_run(session: AsyncSession = Depends(get_session)):
    """Atomically claim the oldest pending **local** run (``FOR UPDATE SKIP LOCKED``).

    Use this from ``poll_local_autopkg.sh`` with ``LOCAL_RUNNER_TOKEN``, or with a normal
    user JWT that has AutoPkg runs write access. Returns **204** when no run is waiting.
    """
    stmt = (
        select(AutoPkgRun)
        .where(AutoPkgRun.runner_type == "local")
        .where(AutoPkgRun.status == RunStatus.pending)
        .order_by(AutoPkgRun.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    async with session.begin():
        result = await session.execute(stmt)
        run = result.scalar_one_or_none()
        if run is None:
            return Response(status_code=204)
        run.status = RunStatus.running
        run.started_at = datetime.now(UTC)
    await session.refresh(run)
    return AutoPkgRunRead.model_validate(run)


@router.get("/runs/config")
async def get_run_config(
    session: AsyncSession = Depends(get_session),
    recipes: str = Query(None, description="Comma-separated recipe names to include"),
):
    """
    Return the configuration needed by the GitHub Actions runner:
    override plist dicts and the set of repos to autopkg repo-add.

    If `recipes` is provided, only those recipes are included.
    Otherwise all enabled overrides are returned.
    """
    query = select(AutoPkgRecipe).where(
        AutoPkgRecipe.is_override.is_(True),
        AutoPkgRecipe.is_enabled.is_(True),
    )
    result = await session.execute(query)
    all_recipes = [r for r in result.scalars().all() if r.trust_status not in TRUST_STATUS_BLOCKS_RUN]

    if recipes:
        names = {n.strip() for n in recipes.split(",") if n.strip()}
        all_recipes = [r for r in all_recipes if r.name in names]

    overrides: list[dict] = []
    repo_urls: set[str] = set()

    for recipe in all_recipes:
        override_entry: dict = {
            "name": recipe.name,
            "identifier": recipe.identifier,
            "plist": _runner_plist_dict_for_recipe(recipe),
        }

        overrides.append(override_entry)

        if recipe.source_repo_full_name:
            repo_urls.add(f"https://github.com/{recipe.source_repo_full_name}.git")
        trust_for_repos = recipe.trust_info
        if not trust_for_repos and recipe.override_data:
            trust_for_repos = recipe.override_data.get("ParentRecipeTrustInfo")
        inferred = infer_repos_from_trust_info(trust_for_repos)
        repo_urls.update(f"https://github.com/{r}.git" for r in inferred)

    return {
        "overrides": overrides,
        "repos": sorted(repo_urls),
        "total_overrides": len(overrides),
        "total_repos": len(repo_urls),
    }


@router.get("/runs/{run_id}", response_model=AutoPkgRunRead)
async def get_run(
    run_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(AutoPkgRun).options(selectinload(AutoPkgRun.results)).where(AutoPkgRun.id == run_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return AutoPkgRunRead.model_validate(run)


@router.post("/runs/{run_id}/results", response_model=RunResultRead)
async def post_run_result(
    run_id: uuid.UUID,
    data: RunResultCreate,
    session: AsyncSession = Depends(get_session),
):
    """Webhook endpoint for the AutoPkg runner to POST per-recipe results."""
    run = await session.get(AutoPkgRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    recipe_result = AutoPkgRunResult(
        run_id=run_id,
        recipe_identifier=data.recipe_identifier,
        recipe_name=data.recipe_name,
        status=RecipeResultStatus(data.status),
        imported_version=data.imported_version,
        imported_display_name=data.imported_display_name,
        imported_pkg_path=data.imported_pkg_path,
        imported_pkginfo_path=data.imported_pkginfo_path,
        imported_catalogs=data.imported_catalogs,
        virustotal_results=data.virustotal_results,
        trust_info_diff=data.trust_info_diff,
        log_output=data.log_output,
        error_message=data.error_message,
        duration_seconds=data.duration_seconds,
    )

    recipe_obj = (
        await session.execute(select(AutoPkgRecipe).where(AutoPkgRecipe.identifier == data.recipe_identifier))
    ).scalar_one_or_none()

    # Match DB row when report script sent a mismatched identifier (e.g. filename heuristics).
    if recipe_obj is None and data.recipe_name:
        name_key = data.recipe_name.strip().lower()
        alt = (
            (await session.execute(select(AutoPkgRecipe).where(func.lower(AutoPkgRecipe.name) == name_key)))
            .scalars()
            .all()
        )
        if len(alt) == 1:
            recipe_obj = alt[0]

    if recipe_obj:
        recipe_obj.last_run_at = datetime.now(UTC)
        recipe_obj.last_run_status = data.status

    if data.status == "trust_failed":
        recipe_result.approval_status = ApprovalStatus.pending
    elif recipe_obj and recipe_obj.auto_promote:
        recipe_result.approval_status = ApprovalStatus.auto_approved
    elif data.status == "imported":
        recipe_result.approval_status = ApprovalStatus.pending
    else:
        recipe_result.approval_status = ApprovalStatus.auto_approved

    session.add(recipe_result)
    await session.commit()
    await session.refresh(recipe_result)
    return RunResultRead.model_validate(recipe_result)


@router.post("/runs/{run_id}/complete")
async def complete_run(
    run_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Called by the runner when the entire run is complete."""
    result = await session.execute(
        select(AutoPkgRun).options(selectinload(AutoPkgRun.results)).where(AutoPkgRun.id == run_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    run.status = RunStatus.completed
    run.completed_at = datetime.now(UTC)
    run.total_recipes = len(run.results)
    run.recipes_succeeded = sum(
        1 for r in run.results if r.status in (RecipeResultStatus.success, RecipeResultStatus.no_change)
    )
    run.recipes_failed = sum(
        1 for r in run.results if r.status in (RecipeResultStatus.failed, RecipeResultStatus.trust_failed)
    )
    run.recipes_imported = sum(1 for r in run.results if r.status == RecipeResultStatus.imported)

    await session.commit()
    return {"message": "Run completed", "run_id": str(run_id)}


def _recipe_input_dict(recipe: AutoPkgRecipe) -> dict | None:
    od = recipe.override_data
    if isinstance(od, dict):
        inner = od.get("Input")
        if isinstance(inner, dict):
            return inner
    iv = recipe.input_variables
    if isinstance(iv, dict):
        return iv
    return None


def _recipe_pkginfo_key(recipe: AutoPkgRecipe) -> str:
    inp = _recipe_input_dict(recipe)
    if isinstance(inp, dict):
        n = inp.get("NAME")
        if isinstance(n, str) and n.strip():
            return n.strip()
    return recipe.name


async def _batch_pkginfo_labels(session: AsyncSession, names: list[str]) -> dict[str, tuple[str | None, str | None]]:
    """Latest ``PkgInfo`` row per ``name`` (by ``updated_at``) for display/icon labels."""
    if not names:
        return {}
    result = await session.execute(
        select(PkgInfo).where(
            PkgInfo.is_deleted.is_(False),
            PkgInfo.name.in_(names),
        )
    )
    rows = result.scalars().all()
    best: dict[str, PkgInfo] = {}
    for p in rows:
        cur = best.get(p.name)
        if cur is None:
            best[p.name] = p
            continue
        if p.updated_at is None:
            continue
        if cur.updated_at is None or p.updated_at > cur.updated_at:
            best[p.name] = p
    out: dict[str, tuple[str | None, str | None]] = {}
    for name, pkg in best.items():
        dn = pkg.display_name.strip() if pkg.display_name and pkg.display_name.strip() else None
        ic = pkg.icon_name.strip() if pkg.icon_name and pkg.icon_name.strip() else None
        out[name] = (dn, ic)
    return out


def _enrich_recipe_read(
    recipe: AutoPkgRecipe,
    labels: dict[str, tuple[str | None, str | None]],
) -> AutoPkgRecipeRead:
    key = _recipe_pkginfo_key(recipe)
    pair = labels.get(key)
    base = AutoPkgRecipeRead.model_validate(recipe)
    if pair is None:
        return base.model_copy(update={"pkginfo_display_name": None, "pkginfo_icon_name": None})
    return base.model_copy(
        update={
            "pkginfo_display_name": pair[0],
            "pkginfo_icon_name": pair[1],
        }
    )


@router.get("/recipes", response_model=list[AutoPkgRecipeRead])
async def list_recipes(
    session: AsyncSession = Depends(get_session),
    enabled_only: bool = Query(False),
):
    query = select(AutoPkgRecipe).order_by(AutoPkgRecipe.name)
    if enabled_only:
        query = query.where(AutoPkgRecipe.is_enabled.is_(True))
    result = await session.execute(query)
    recipes = result.scalars().all()
    keys = list({_recipe_pkginfo_key(r) for r in recipes})
    labels = await _batch_pkginfo_labels(session, keys)
    return [_enrich_recipe_read(r, labels) for r in recipes]


@router.get("/recipes/{recipe_id}/runner-override.plist")
async def download_runner_override_plist(
    recipe_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """
    XML plist of the override in the same form as ``overrides[].plist`` in
    ``GET /autopkg/runs/config`` (including merged DB trust for runners).
    """
    recipe = await session.get(AutoPkgRecipe, recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    plist_dict = _runner_plist_dict_for_recipe(recipe)
    body = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)
    safe_name = re.sub(r"[^\w.\-]+", "_", recipe.name).strip("._") or "override"
    filename = f"{safe_name}.recipe.plist"
    return Response(
        content=body,
        media_type="application/x-plist",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/recipes", response_model=AutoPkgRecipeRead)
async def create_recipe(
    data: AutoPkgRecipeCreate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    existing = await session.execute(select(AutoPkgRecipe).where(AutoPkgRecipe.identifier == data.identifier))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Recipe already exists")

    recipe = AutoPkgRecipe(**data.model_dump(exclude={"github_repo", "recipe_path"}))
    _normalize_pkginfo_into_override_only(recipe)
    session.add(recipe)

    await create_audit_entry(
        session,
        action="create",
        entity_type="autopkg_recipe",
        entity_id=str(recipe.id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )

    await session.commit()
    await session.refresh(recipe)
    return AutoPkgRecipeRead.model_validate(recipe)


@router.post("/recipes/import-override", response_model=AutoPkgRecipeRead)
async def import_recipe_override(
    data: AutoPkgRecipeImportOverrideRequest,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    """
    Import an existing AutoPkg override plist (from ``RecipeOverrides`` or a repo)
    into ``autopkg_recipe``. Optionally re-resolve trust from GitHub.
    """
    parsed = _parse_imported_override_content(data.content)
    identifier = parsed.get("Identifier")
    parent_recipe = parsed.get("ParentRecipe")
    if not identifier or not isinstance(identifier, str):
        raise HTTPException(status_code=400, detail="Override must include a string Identifier")
    if not parent_recipe or not isinstance(parent_recipe, str):
        raise HTTPException(
            status_code=400,
            detail="Override must include a string ParentRecipe (this must be an override, not a full recipe)",
        )

    existing = await session.execute(select(AutoPkgRecipe).where(AutoPkgRecipe.identifier == identifier))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A recipe with this identifier already exists")

    input_dict = dict(parsed.get("Input") or {})
    input_variables_for_db = _strip_pkginfo_from_input(input_dict if input_dict else None)

    name = (data.name or "").strip() or identifier.rsplit(".", 1)[-1]

    source_repo: str | None = None
    if data.source_repo_full_name and str(data.source_repo_full_name).strip():
        try:
            source_repo = normalize_github_full_name(str(data.source_repo_full_name))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    override_plist: dict = {
        "Identifier": identifier,
        "ParentRecipe": parent_recipe,
        "Input": input_dict,
    }
    for key in ("MinimumVersion", "Process"):
        if key in parsed:
            override_plist[key] = parsed[key]
    if isinstance(parsed.get("ParentRecipeTrustInfo"), dict):
        override_plist["ParentRecipeTrustInfo"] = parsed["ParentRecipeTrustInfo"]

    plist_trust_raw = parsed.get("ParentRecipeTrustInfo")
    trust_from_plist = (
        trust_info_from_plist_parent_recipe_trust(plist_trust_raw) if isinstance(plist_trust_raw, dict) else None
    )

    trust_info: dict | None = None
    trust_status = TrustStatus.unknown.value
    trust_verified_at = None

    if data.refresh_trust:
        location_cache = await build_location_cache(session)
        try:
            new_trust = await compute_trust_info(
                parent_recipe,
                existing_trust_info=trust_from_plist,
                location_cache=location_cache,
            )
        except GitHubRateLimitError:
            raise HTTPException(
                status_code=503,
                detail="GitHub API rate limit exceeded. Try again later or import with refresh_trust=false.",
            ) from None
        if new_trust.get("parent_recipes"):
            trust_info = new_trust
            trust_status = TrustStatus.verified.value
            trust_verified_at = datetime.now(UTC)
            override_plist["ParentRecipeTrustInfo"] = _plist_trust_snippet_from_db_trust(new_trust)
        elif trust_from_plist and (
            trust_from_plist.get("parent_recipes") or trust_from_plist.get("non_core_processors")
        ):
            trust_info = trust_from_plist
    elif trust_from_plist and (trust_from_plist.get("parent_recipes") or trust_from_plist.get("non_core_processors")):
        trust_info = trust_from_plist

    recipe = AutoPkgRecipe(
        identifier=identifier,
        name=name,
        parent_recipe=parent_recipe,
        source_repo_full_name=source_repo,
        override_data=override_plist,
        trust_info=trust_info,
        input_variables=input_variables_for_db,
        is_override=True,
        is_enabled=data.is_enabled,
        auto_promote=data.auto_promote,
        trust_status=trust_status,
        trust_verified_at=trust_verified_at,
    )
    _normalize_pkginfo_into_override_only(recipe)
    session.add(recipe)

    await create_audit_entry(
        session,
        action="import_override",
        entity_type="autopkg_recipe",
        entity_id=str(recipe.id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        after_snapshot={"identifier": identifier, "refresh_trust": data.refresh_trust},
    )

    await session.commit()
    await session.refresh(recipe)
    return AutoPkgRecipeRead.model_validate(recipe)


@router.put("/recipes/{recipe_id}", response_model=AutoPkgRecipeRead)
async def update_recipe(
    recipe_id: uuid.UUID,
    data: AutoPkgRecipeUpdate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    recipe = await session.get(AutoPkgRecipe, recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(recipe, field, value)

    _normalize_pkginfo_into_override_only(recipe)

    await create_audit_entry(
        session,
        action="update",
        entity_type="autopkg_recipe",
        entity_id=str(recipe_id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        changes=update_data,
    )

    await session.commit()
    await session.refresh(recipe)
    return AutoPkgRecipeRead.model_validate(recipe)


@router.delete("/recipes/{recipe_id}")
async def delete_recipe(
    recipe_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    recipe = await session.get(AutoPkgRecipe, recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")

    await create_audit_entry(
        session,
        action="delete",
        entity_type="autopkg_recipe",
        entity_id=str(recipe_id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )

    await session.delete(recipe)
    await session.commit()
    return {"message": f"Recipe {recipe.name} deleted"}


@router.get("/recipes/discover", response_model=list[GitHubRecipeRepoRead])
async def discover_recipes(session: AsyncSession = Depends(get_session)):
    """List all cached GitHub recipe repos from the local DB."""
    result = await session.execute(
        select(GitHubRecipeRepo)
        .options(selectinload(GitHubRecipeRepo.cached_recipes))
        .order_by(GitHubRecipeRepo.stars.desc(), GitHubRecipeRepo.name)
    )
    repos = result.scalars().unique().all()
    return [GitHubRecipeRepoRead.model_validate(r) for r in repos]


@router.get("/recipes/discover/{repo_owner}/{repo_name}")
async def discover_repo_recipes(
    repo_owner: str,
    repo_name: str,
    session: AsyncSession = Depends(get_session),
):
    """List cached recipes for a specific repo. If none cached, fetch live."""
    full_name = f"{repo_owner}/{repo_name}"
    repo = (
        await session.execute(
            select(GitHubRecipeRepo)
            .options(selectinload(GitHubRecipeRepo.cached_recipes))
            .where(GitHubRecipeRepo.full_name == full_name)
        )
    ).scalar_one_or_none()

    if repo and repo.cached_recipes:
        recipes = [
            {
                "name": r.name,
                "filename": r.filename,
                "path": r.path,
                "identifier_guess": r.identifier_guess,
                "repo_full_name": full_name,
                "url": r.url,
            }
            for r in repo.cached_recipes
        ]
        return {
            "recipes": recipes,
            "total": len(recipes),
            "repo": full_name,
            "cached": True,
        }

    recipes = await discover_recipes_in_repo(full_name)
    if repo and recipes:
        await sync_repo_recipes_to_cache(session, repo)
    return {
        "recipes": recipes,
        "total": len(recipes),
        "repo": full_name,
        "cached": False,
    }


@router.get("/recipes/search")
async def search_recipes(
    q: str = Query(..., min_length=2),
    session: AsyncSession = Depends(get_session),
):
    """Search locally cached recipes by name, path, or identifier."""
    pattern = f"%{q}%"
    result = await session.execute(
        select(GitHubRecipe)
        .where(
            or_(
                GitHubRecipe.name.ilike(pattern),
                GitHubRecipe.path.ilike(pattern),
                GitHubRecipe.identifier_guess.ilike(pattern),
            )
        )
        .options(selectinload(GitHubRecipe.repo))
        .limit(200)
    )
    recipes = result.scalars().all()
    results = [
        {
            "name": r.name,
            "filename": r.filename,
            "path": r.path,
            "identifier_guess": r.identifier_guess,
            "repo_full_name": r.repo.full_name if r.repo else "",
            "repo_name": r.repo.name if r.repo else "",
            "repo_url": r.repo.html_url if r.repo else "",
            "url": r.url,
        }
        for r in recipes
    ]
    return {"results": results, "total": len(results)}


# ── Trust verification ────────────────────────────────────────────────────


@router.get("/recipes/trust-status", response_model=list[AutoPkgRecipeRead])
async def list_trust_status(
    session: AsyncSession = Depends(get_session),
    status: str | None = Query(None),
):
    """List all recipes with their trust status. Optionally filter by status."""
    query = select(AutoPkgRecipe).where(AutoPkgRecipe.is_override.is_(True)).order_by(AutoPkgRecipe.name)
    if status:
        query = query.where(AutoPkgRecipe.trust_status == status)
    result = await session.execute(query)
    recipes = result.scalars().all()
    keys = list({_recipe_pkginfo_key(r) for r in recipes})
    labels = await _batch_pkginfo_labels(session, keys)
    return [_enrich_recipe_read(r, labels) for r in recipes]


@router.post("/recipes/{recipe_id}/verify-trust")
async def verify_recipe_trust(
    recipe_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    """
    Verify trust for a single recipe by comparing stored trust_info
    against freshly computed hashes from GitHub.
    """
    recipe = await session.get(AutoPkgRecipe, recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")

    result = await verify_trust(
        stored_trust_info=recipe.trust_info,
        parent_recipe_identifier=recipe.parent_recipe,
    )

    recipe.trust_verified_at = datetime.now(UTC)

    if result.status == "verified":
        recipe.trust_status = "verified"
    elif result.status == "failed":
        recipe.trust_status = "pending_approval"

        location_cache = await build_location_cache(session)
        new_trust = await compute_trust_info(
            recipe.parent_recipe,
            existing_trust_info=recipe.trust_info,
            location_cache=location_cache,
        )
        change_request = TrustChangeRequest(
            recipe_id=recipe.id,
            old_trust_info=recipe.trust_info,
            new_trust_info=new_trust,
            diff=result.diff,
            status="pending",
        )
        session.add(change_request)
    else:
        recipe.trust_status = "unknown"

    await create_audit_entry(
        session,
        action="verify_trust",
        entity_type="autopkg_recipe",
        entity_id=str(recipe_id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        notes=f"Trust status: {result.status}" + (f" - {result.error}" if result.error else ""),
    )

    await session.commit()
    await session.refresh(recipe)
    return {
        "recipe_id": str(recipe_id),
        "name": recipe.name,
        "trust_status": recipe.trust_status,
        "diff": result.diff if result.diff else None,
        "error": result.error,
    }


@router.post("/recipes/{recipe_id}/update-trust")
async def update_recipe_trust(
    recipe_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    """
    Update trust info for a recipe with freshly computed values.
    Re-resolves all parent recipes and stores github_repo/github_path
    for fast future verification. Should only be called after approval.
    """
    recipe = await session.get(AutoPkgRecipe, recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")

    location_cache = await build_location_cache(session)

    try:
        new_trust = await compute_trust_info(
            recipe.parent_recipe,
            existing_trust_info=recipe.trust_info,
            location_cache=location_cache,
        )
    except GitHubRateLimitError:
        raise HTTPException(
            status_code=503,
            detail="GitHub API rate limit exceeded. Please try again later.",
        )

    if not new_trust.get("parent_recipes"):
        raise HTTPException(
            status_code=502,
            detail="Could not resolve parent recipes from GitHub. Check that the parent recipe identifier is correct.",
        )

    old_trust = recipe.trust_info
    recipe.trust_info = new_trust
    recipe.trust_status = "verified"
    recipe.trust_verified_at = datetime.now(UTC)
    recipe.trust_approved_by = user.email if user else "system"
    recipe.trust_approved_at = datetime.now(UTC)

    plist_trust = _plist_trust_snippet_from_db_trust(new_trust)
    if recipe.override_data is not None:
        od = dict(recipe.override_data)
        od["ParentRecipeTrustInfo"] = plist_trust
        recipe.override_data = od

    await create_audit_entry(
        session,
        action="update_trust",
        entity_type="autopkg_recipe",
        entity_id=str(recipe_id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        before_snapshot={"trust_info": old_trust},
        after_snapshot={"trust_info": new_trust},
    )

    await session.commit()
    return {
        "recipe_id": str(recipe_id),
        "name": recipe.name,
        "trust_status": "verified",
    }


@router.post("/recipes/{recipe_id}/approve-trust")
async def approve_recipe_trust(
    recipe_id: uuid.UUID,
    data: TrustApprovalRequest,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    """
    Approve or reject a pending trust change. If approved, updates the
    stored trust_info with the new computed values.
    """
    recipe = await session.get(AutoPkgRecipe, recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")

    pending_requests = await session.execute(
        select(TrustChangeRequest)
        .where(TrustChangeRequest.recipe_id == recipe_id)
        .where(TrustChangeRequest.status == "pending")
        .order_by(TrustChangeRequest.requested_at.desc())
    )
    change_request = pending_requests.scalars().first()
    if not change_request:
        raise HTTPException(status_code=400, detail="No pending trust change request")

    reviewer = user.email if user else "anonymous"
    now = datetime.now(UTC)

    if data.approved:
        change_request.status = "approved"
        change_request.reviewed_by = reviewer
        change_request.reviewed_at = now
        change_request.comment = data.comment

        new_trust = change_request.new_trust_info
        recipe.trust_info = new_trust
        recipe.trust_status = "verified"
        recipe.trust_approved_by = reviewer
        recipe.trust_approved_at = now
        plist_trust = _plist_trust_snippet_from_db_trust(new_trust)
        if recipe.override_data is not None:
            od = dict(recipe.override_data)
            od["ParentRecipeTrustInfo"] = plist_trust
            recipe.override_data = od
    else:
        change_request.status = "rejected"
        change_request.reviewed_by = reviewer
        change_request.reviewed_at = now
        change_request.comment = data.comment

        recipe.trust_status = "failed"

    await create_audit_entry(
        session,
        action="approve_trust" if data.approved else "reject_trust",
        entity_type="autopkg_recipe",
        entity_id=str(recipe_id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        notes=data.comment,
    )

    await session.commit()
    return {
        "recipe_id": str(recipe_id),
        "name": recipe.name,
        "trust_status": recipe.trust_status,
        "approved": data.approved,
    }


@router.get(
    "/trust-changes",
    response_model=list[TrustChangeRequestRead],
)
async def list_trust_changes(
    session: AsyncSession = Depends(get_session),
    status: str | None = Query(None),
):
    """List trust change requests, optionally filtered by status."""
    query = select(TrustChangeRequest).order_by(TrustChangeRequest.requested_at.desc())
    if status:
        query = query.where(TrustChangeRequest.status == status)
    result = await session.execute(query)
    return [TrustChangeRequestRead.model_validate(r) for r in result.scalars().all()]


@router.post(
    "/trust/resolve-commit",
    response_model=TrustCommitResolveResponse,
)
async def resolve_trust_commit(
    data: TrustCommitResolveRequest,
    user: User | None = Depends(current_optional_user),
):
    """
    Map a trust hash diff to a GitHub commit URL by walking recent history
    for the file and matching SHA-256 content hashes (not git blob SHAs).
    """
    _ = user  # auth required via dependency
    repo = data.github_repo.strip().removesuffix("/")
    if repo.count("/") != 1 or ".." in repo or repo.startswith("/"):
        raise HTTPException(status_code=400, detail="github_repo must be owner/repo")
    path = data.github_path.strip().lstrip("/")
    if not path or any(p in ("", ".", "..") for p in path.split("/")):
        raise HTTPException(status_code=400, detail="Invalid github_path")

    new_h = data.new_sha256.strip().lower()
    old_h = data.old_sha256.strip().lower() if data.old_sha256 else None
    if not new_h:
        raise HTTPException(status_code=400, detail="new_sha256 is required")

    try:
        sha = await resolve_introducing_commit(repo, path, new_h, old_h)
    except GitHubRateLimitError as exc:
        raise HTTPException(
            status_code=429,
            detail="GitHub API rate limit exceeded. Try again later.",
        ) from exc

    if not sha:
        return TrustCommitResolveResponse(commit_sha=None, commit_url=None)
    return TrustCommitResolveResponse(
        commit_sha=sha,
        commit_url=f"https://github.com/{repo}/commit/{sha}",
    )


@router.post("/repos/update")
async def update_repos_and_verify_trust(
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    """
    Trigger a 'repo update': re-fetch recipe file hashes from GitHub
    for all enabled overrides, then run trust verification on each.
    Returns a summary of results.
    """
    result = await session.execute(
        select(AutoPkgRecipe).where(
            AutoPkgRecipe.is_override.is_(True),
            AutoPkgRecipe.is_enabled.is_(True),
            AutoPkgRecipe.trust_info.isnot(None),
        )
    )
    recipes = result.scalars().all()

    summary = {"total": len(recipes), "verified": 0, "failed": 0, "errors": 0}

    location_cache = await build_location_cache(session)

    rate_limited = False
    for recipe in recipes:
        if rate_limited:
            summary["errors"] += 1
            continue
        try:
            verification = await verify_trust(
                stored_trust_info=recipe.trust_info,
                parent_recipe_identifier=recipe.parent_recipe,
            )
            recipe.trust_verified_at = datetime.now(UTC)

            if verification.status == "verified":
                recipe.trust_status = "verified"
                summary["verified"] += 1
            elif verification.status == "failed":
                recipe.trust_status = "pending_approval"

                new_trust = await compute_trust_info(
                    recipe.parent_recipe,
                    existing_trust_info=recipe.trust_info,
                    location_cache=location_cache,
                )
                change_request = TrustChangeRequest(
                    recipe_id=recipe.id,
                    old_trust_info=recipe.trust_info,
                    new_trust_info=new_trust,
                    diff=verification.diff,
                    status="pending",
                )
                session.add(change_request)
                summary["failed"] += 1
            elif verification.error and "rate limit" in verification.error.lower():
                rate_limited = True
                summary["errors"] += 1
            else:
                summary["errors"] += 1
        except GitHubRateLimitError:
            rate_limited = True
            summary["errors"] += 1
        except Exception:
            summary["errors"] += 1

    if rate_limited:
        summary["rate_limited"] = True

    await create_audit_entry(
        session,
        action="repo_update",
        entity_type="autopkg_system",
        entity_id="trust_verification",
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        after_snapshot=summary,
    )

    await session.commit()
    return summary


# ── GitHub cache sync ────────────────────────────────────────────────────


@router.post("/cache/sync-repos")
async def sync_repos(session: AsyncSession = Depends(get_session)):
    """Sync the list of autopkg recipe repos from GitHub into the local cache."""
    result = await sync_repos_to_cache(session)
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return result


@router.post("/cache/sync-recipes")
async def sync_recipes(session: AsyncSession = Depends(get_session)):
    """Sync all recipes for all cached repos. This can take a while."""
    return await sync_all_recipes_to_cache(session)


@router.post("/cache/sync-repo/{repo_owner}/{repo_name}")
async def sync_single_repo(
    repo_owner: str,
    repo_name: str,
    session: AsyncSession = Depends(get_session),
):
    """Sync recipes for a single cached repo."""
    full_name = f"{repo_owner}/{repo_name}"
    repo = (
        await session.execute(select(GitHubRecipeRepo).where(GitHubRecipeRepo.full_name == full_name))
    ).scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repo not in cache. Sync repos first.")
    count = await sync_repo_recipes_to_cache(session, repo)
    return {"repo": full_name, "recipes_synced": count}


@router.post("/cache/repos", response_model=GitHubRecipeRepoRead)
async def add_manual_github_repo(
    data: GitHubCustomRepoAdd,
    session: AsyncSession = Depends(get_session),
):
    """Add any public GitHub repo to the discover cache (outside the autopkg org)."""
    try:
        repo = await add_custom_repo_to_cache(session, data.full_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    loaded = (
        await session.execute(
            select(GitHubRecipeRepo)
            .options(selectinload(GitHubRecipeRepo.cached_recipes))
            .where(GitHubRecipeRepo.id == repo.id)
        )
    ).scalar_one()
    return GitHubRecipeRepoRead.model_validate(loaded)


@router.delete("/cache/repos/{repo_owner}/{repo_name}")
async def remove_cached_github_repo(
    repo_owner: str,
    repo_name: str,
    session: AsyncSession = Depends(get_session),
):
    """Remove a repo from the discover cache (and its cached recipe index). Org repos reappear on Sync Repos."""
    try:
        full_name = normalize_github_full_name(f"{repo_owner}/{repo_name}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    ok = await remove_github_repo_from_cache(session, full_name)
    if not ok:
        raise HTTPException(status_code=404, detail="Repo not in cache")
    return {"removed": full_name}


@router.post("/recipes/add-override", response_model=AutoPkgRecipeRead)
async def add_recipe_override(
    data: AutoPkgRecipeCreate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    """
    Add a discovered recipe as an override in the DB.
    Requires github_repo and recipe_path to fetch the actual recipe
    content and populate identifier, input_variables, trust_info, and parent_recipe.
    """
    if not data.github_repo or not data.recipe_path:
        raise HTTPException(
            status_code=400,
            detail="github_repo and recipe_path are required to create an override",
        )

    try:
        recipe_content = await fetch_recipe_content(data.github_repo, data.recipe_path)
    except GitHubRateLimitError:
        raise HTTPException(
            status_code=503,
            detail="GitHub API rate limit exceeded. Please try again later.",
        )

    if not recipe_content:
        raise HTTPException(
            status_code=502,
            detail=f"Could not fetch recipe from GitHub: {data.github_repo}/{data.recipe_path}",
        )

    location_cache = await build_location_cache(session)

    try:
        override_info = await build_override_data(
            recipe_content,
            data.github_repo,
            data.recipe_path,
            location_cache=location_cache,
        )
    except GitHubRateLimitError:
        raise HTTPException(
            status_code=503,
            detail="GitHub API rate limit exceeded while building override. Please try again later.",
        )

    trust_info = override_info.get("trust_info", {})
    input_variables = override_info.get("input_variables", {})
    input_variables_for_db = _strip_pkginfo_from_input(input_variables if input_variables else None)

    override_plist = {
        "Identifier": override_info["identifier"],
        "ParentRecipe": override_info["parent_recipe"],
        "Input": input_variables or {},
    }
    override_plist["ParentRecipeTrustInfo"] = _plist_trust_snippet_from_db_trust(trust_info)

    payload = {
        "identifier": override_info["identifier"],
        "name": data.name,
        "parent_recipe": override_info["parent_recipe"],
        "input_variables": input_variables_for_db,
        "trust_info": trust_info,
        "override_data": override_plist,
        "source_repo_full_name": data.github_repo,
        "is_override": True,
        "is_enabled": data.is_enabled,
        "auto_promote": data.auto_promote,
        "trust_status": "verified",
    }

    existing = await session.execute(select(AutoPkgRecipe).where(AutoPkgRecipe.identifier == payload["identifier"]))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Recipe override already exists")

    recipe = AutoPkgRecipe(**payload)
    session.add(recipe)

    audit_snapshot = {**payload}
    await create_audit_entry(
        session,
        action="create_override",
        entity_type="autopkg_recipe",
        entity_id=str(recipe.id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        after_snapshot=audit_snapshot,
    )

    await session.commit()
    await session.refresh(recipe)
    return AutoPkgRecipeRead.model_validate(recipe)


# ── Inferred repos ────────────────────────────────────────────────────────


@router.get("/repos/inferred")
async def list_inferred_repos(
    session: AsyncSession = Depends(get_session),
):
    """
    Return the set of GitHub repos needed for autopkg runs.
    Uses ``source_repo_full_name`` on each recipe when set,
    falling back to inference from ``trust_info`` for legacy recipes.
    """
    result = await session.execute(
        select(AutoPkgRecipe).where(
            AutoPkgRecipe.is_override.is_(True),
            AutoPkgRecipe.is_enabled.is_(True),
        )
    )
    recipes = result.scalars().all()

    all_repos: set[str] = set()
    for recipe in recipes:
        if recipe.source_repo_full_name:
            all_repos.add(recipe.source_repo_full_name)
        elif recipe.trust_info:
            inferred = infer_repos_from_trust_info(recipe.trust_info)
            all_repos.update(inferred)

    return {
        "repos": sorted(all_repos),
        "total": len(all_repos),
        "recipe_count": len(recipes),
    }


@router.post("/results/{result_id}/approve")
async def approve_result(
    result_id: uuid.UUID,
    data: ApprovalRequest,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    result = await session.get(AutoPkgRunResult, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    if result.approval_status != ApprovalStatus.pending:
        raise HTTPException(status_code=400, detail="Result is not pending approval")

    result.approval_status = ApprovalStatus.approved if data.approved else ApprovalStatus.rejected
    result.approved_by = user.email if user else "anonymous"
    result.approved_at = datetime.now(UTC)
    result.approval_comment = data.comment

    await create_audit_entry(
        session,
        action="approve" if data.approved else "reject",
        entity_type="autopkg_run_result",
        entity_id=str(result_id),
        entity_name=result.imported_display_name or result.recipe_name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        notes=data.comment,
    )

    await session.commit()
    return {"message": "Approved" if data.approved else "Rejected"}


@router.get("/approvals", response_model=list[RunResultRead])
async def list_pending_approvals(
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(AutoPkgRunResult)
        .where(AutoPkgRunResult.approval_status == ApprovalStatus.pending)
        .order_by(AutoPkgRunResult.created_at.desc())
    )
    return [RunResultRead.model_validate(r) for r in result.scalars().all()]


# ── Metadata cache ───────────────────────────────────────────────────────


@router.get("/metadata-cache", response_model=MetadataCacheRead)
async def get_metadata_cache(
    session: AsyncSession = Depends(get_session),
):
    """Return the stored cloud-autopkg-runner metadata cache (one DB row per recipe)."""
    result = await session.execute(select(AutoPkgMetadataCacheEntry))
    rows = result.scalars().all()
    if not rows:
        return MetadataCacheRead(cache_data={}, updated_at=datetime.now(UTC))
    cache_data: dict = {}
    latest: datetime | None = None
    for r in rows:
        cache_data[r.recipe_key] = r.entry
        if latest is None or r.updated_at > latest:
            latest = r.updated_at
    return MetadataCacheRead(cache_data=cache_data, updated_at=latest or datetime.now(UTC))


@router.put("/metadata-cache", response_model=MetadataCacheRead)
async def put_metadata_cache(
    data: MetadataCacheWrite,
    session: AsyncSession = Depends(get_session),
):
    """Replace the metadata cache from the runner's aggregated JSON (per-recipe rows in DB)."""
    await session.execute(delete(AutoPkgMetadataCacheEntry))
    now = datetime.now(UTC)
    for key, entry in data.cache_data.items():
        if isinstance(entry, dict):
            session.add(AutoPkgMetadataCacheEntry(recipe_key=key, entry=entry, updated_at=now))
    await session.commit()
    return MetadataCacheRead(cache_data=data.cache_data, updated_at=now)


@router.delete("/metadata-cache")
async def delete_metadata_cache(
    recipe_key: str | None = Query(
        None,
        description="If set, delete only this recipe's cache key (e.g. AdobeReader.munki.recipe). "
        "Omit to clear the entire cache.",
    ),
    session: AsyncSession = Depends(get_session),
):
    """
    Remove cloud-autopkg-runner metadata cache entries.

    Stale entries cause **no_change** on the next run even after you delete a pkginfo:
    the runner still believes upstream matches the cached version. Clear the recipe's
    key (or the whole cache) before re-importing.
    """
    if recipe_key:
        result = await session.execute(
            delete(AutoPkgMetadataCacheEntry).where(AutoPkgMetadataCacheEntry.recipe_key == recipe_key)
        )
        deleted = result.rowcount or 0
        if deleted == 0:
            raise HTTPException(
                status_code=404,
                detail=f"No metadata cache entry for recipe_key={recipe_key!r}",
            )
        await session.commit()
        return {"deleted": deleted, "recipe_key": recipe_key}

    result = await session.execute(delete(AutoPkgMetadataCacheEntry))
    deleted = result.rowcount or 0
    await session.commit()
    return {"deleted": deleted, "recipe_key": None}


# ── Pkginfo ingestion ────────────────────────────────────────────────────


@router.post("/pkginfo/ingest")
async def ingest_pkginfo(
    data: PkgInfoIngest,
    session: AsyncSession = Depends(get_session),
):
    """Ingest a pkginfo plist dict from an AutoPkg run.

    Creates a PkgInfo row and associates it with the appropriate catalogs.
    Returns 200 with ``skipped=true`` if the name+version already exists.
    """
    plist = data.pkginfo
    name = plist.get("name")
    version = plist.get("version")
    if not name or not version:
        raise HTTPException(status_code=422, detail="pkginfo must contain 'name' and 'version'")

    existing = await session.execute(select(PkgInfo).where(PkgInfo.name == name, PkgInfo.version == version))
    if existing.scalar_one_or_none():
        return {
            "message": "Already exists",
            "skipped": True,
            "name": name,
            "version": version,
        }

    raw_catalogs = plist.get("catalogs", [])
    if isinstance(raw_catalogs, str):
        catalog_names = [c.strip() for c in re.split(r"[,/|]+", raw_catalogs) if c.strip()]
    elif isinstance(raw_catalogs, list):
        catalog_names = [str(x).strip() for x in raw_catalogs if str(x).strip()]
    else:
        catalog_names = []

    pkg = PkgInfo(
        name=name,
        version=version,
        display_name=plist.get("display_name"),
        description=plist.get("description"),
        category=plist.get("category"),
        developer=plist.get("developer"),
        icon_name=plist.get("icon_name"),
        installer_item_location=plist.get("installer_item_location"),
        installer_item_hash=plist.get("installer_item_hash"),
        installer_item_size=plist.get("installer_item_size"),
        installed_size=plist.get("installed_size"),
        installer_type=plist.get("installer_type"),
        minimum_os_version=plist.get("minimum_os_version"),
        maximum_os_version=plist.get("maximum_os_version"),
        uninstall_method=plist.get("uninstall_method"),
        unattended_install=plist.get("unattended_install", False),
        unattended_uninstall=plist.get("unattended_uninstall", False),
        autoremove=plist.get("autoremove", False),
        uninstallable=plist.get("uninstallable", True),
        installs=plist.get("installs"),
        receipts=plist.get("receipts"),
        blocking_applications=plist.get("blocking_applications"),
        items_to_copy=plist.get("items_to_copy"),
        supported_architectures=plist.get("supported_architectures"),
        requires=plist.get("requires"),
        update_for=plist.get("update_for"),
        preinstall_script=plist.get("preinstall_script"),
        postinstall_script=plist.get("postinstall_script"),
        preuninstall_script=plist.get("preuninstall_script"),
        postuninstall_script=plist.get("postuninstall_script"),
        installcheck_script=plist.get("installcheck_script"),
        uninstallcheck_script=plist.get("uninstallcheck_script"),
        metadata_=plist.get("_metadata"),
        raw_plist=None,
    )
    session.add(pkg)
    await session.flush()

    for cat_name in catalog_names:
        result = await session.execute(select(Catalog).where(Catalog.name == cat_name))
        catalog = result.scalar_one_or_none()
        if not catalog:
            catalog = Catalog(name=cat_name)
            session.add(catalog)
            await session.flush()
        session.add(PkgInfoCatalog(pkg_info_id=pkg.id, catalog_id=catalog.id))

    await session.flush()
    pkg_sync = (
        await session.execute(select(PkgInfo).options(selectinload(PkgInfo.catalogs)).where(PkgInfo.id == pkg.id))
    ).scalar_one()
    sync_pkginfo_raw_plist(pkg_sync)
    await session.commit()
    return {
        "message": "Ingested",
        "skipped": False,
        "name": name,
        "version": version,
        "id": str(pkg.id),
    }
