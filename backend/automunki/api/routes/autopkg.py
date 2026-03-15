import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.api.deps import get_session
from automunki.core.security import current_optional_user
from automunki.models.autopkg import (
    ApprovalStatus,
    AutoPkgRecipe,
    AutoPkgRepo,
    AutoPkgRun,
    AutoPkgRunResult,
    GitHubRecipe,
    GitHubRecipeRepo,
    RecipeResultStatus,
    RunStatus,
    RunTriggerType,
    TrustChangeRequest,
)
from automunki.models.user import User
from automunki.schemas.autopkg import (
    ApprovalRequest,
    AutoPkgRecipeCreate,
    AutoPkgRecipeRead,
    AutoPkgRecipeUpdate,
    AutoPkgRunRead,
    GitHubRecipeRepoRead,
    RunResultCreate,
    RunResultRead,
    TriggerRunRequest,
    TrustApprovalRequest,
    TrustChangeRequestRead,
)
from automunki.schemas.common import PaginatedResponse
from automunki.services.audit import create_audit_entry
from automunki.services.autopkg import (
    discover_recipes_in_repo,
    dispatch_autopkg_workflow,
    sync_all_recipes_to_cache,
    sync_repo_recipes_to_cache,
    sync_repos_to_cache,
)
from automunki.services.trust import (
    GitHubRateLimitError,
    build_location_cache,
    build_override_data,
    compute_trust_info,
    fetch_recipe_content,
    infer_repos_from_trust_info,
    verify_trust,
)

router = APIRouter(prefix="/autopkg", tags=["autopkg"])


@router.post("/runs", response_model=AutoPkgRunRead)
async def trigger_run(
    data: TriggerRunRequest,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    run = AutoPkgRun(
        status=RunStatus.pending,
        trigger_type=RunTriggerType.manual_ui,
        triggered_by=user.email if user else "anonymous",
        recipe_filter=data.recipe_names,
    )
    session.add(run)
    await session.flush()

    result = await dispatch_autopkg_workflow(
        run_id=str(run.id),
        recipe_names=data.recipe_names,
    )

    if "error" in result:
        run.status = RunStatus.failed
        run.error_message = result["error"]
    else:
        run.status = RunStatus.running
        run.started_at = datetime.now(timezone.utc)

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
    count = (
        await session.execute(select(func.count()).select_from(AutoPkgRun))
    ).scalar() or 0

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


@router.get("/runs/config")
async def get_run_config(
    session: AsyncSession = Depends(get_session),
    recipes: str = Query(
        None, description="Comma-separated recipe names to include"
    ),
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
    all_recipes = result.scalars().all()

    if recipes:
        names = {n.strip() for n in recipes.split(",") if n.strip()}
        all_recipes = [r for r in all_recipes if r.name in names]

    overrides: list[dict] = []
    repo_urls: set[str] = set()

    for recipe in all_recipes:
        override_entry: dict = {
            "name": recipe.name,
            "identifier": recipe.identifier,
        }
        if recipe.override_data:
            plist = dict(recipe.override_data)
            trust = plist.get("ParentRecipeTrustInfo", {})
            trust.setdefault("parent_recipes", {})
            trust.setdefault("non_core_processors", {})
            if trust:
                plist["ParentRecipeTrustInfo"] = trust
            override_entry["plist"] = plist
        else:
            override_entry["plist"] = {
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
                override_entry["plist"]["ParentRecipeTrustInfo"] = plist_trust

        overrides.append(override_entry)

        if recipe.repo:
            repo_urls.add(recipe.repo.url)
        else:
            inferred = infer_repos_from_trust_info(recipe.trust_info)
            repo_urls.update(
                f"https://github.com/{r}.git" for r in inferred
            )

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
        select(AutoPkgRun)
        .options(selectinload(AutoPkgRun.results))
        .where(AutoPkgRun.id == run_id)
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
        imported_pkg_path=data.imported_pkg_path,
        imported_pkginfo_path=data.imported_pkginfo_path,
        imported_catalogs=data.imported_catalogs,
        virustotal_results=data.virustotal_results,
        trust_info_diff=data.trust_info_diff,
        log_output=data.log_output,
        error_message=data.error_message,
        duration_seconds=data.duration_seconds,
    )

    recipe = await session.execute(
        select(AutoPkgRecipe).where(AutoPkgRecipe.identifier == data.recipe_identifier)
    )
    recipe_obj = recipe.scalar_one_or_none()

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
        select(AutoPkgRun)
        .options(selectinload(AutoPkgRun.results))
        .where(AutoPkgRun.id == run_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    run.status = RunStatus.completed
    run.completed_at = datetime.now(timezone.utc)
    run.total_recipes = len(run.results)
    run.recipes_succeeded = sum(
        1
        for r in run.results
        if r.status in (RecipeResultStatus.success, RecipeResultStatus.no_change)
    )
    run.recipes_failed = sum(
        1
        for r in run.results
        if r.status in (RecipeResultStatus.failed, RecipeResultStatus.trust_failed)
    )
    run.recipes_imported = sum(
        1 for r in run.results if r.status == RecipeResultStatus.imported
    )

    await session.commit()
    return {"message": "Run completed", "run_id": str(run_id)}


@router.get("/recipes", response_model=list[AutoPkgRecipeRead])
async def list_recipes(
    session: AsyncSession = Depends(get_session),
    enabled_only: bool = Query(False),
):
    query = select(AutoPkgRecipe).order_by(AutoPkgRecipe.name)
    if enabled_only:
        query = query.where(AutoPkgRecipe.is_enabled.is_(True))
    result = await session.execute(query)
    return [AutoPkgRecipeRead.model_validate(r) for r in result.scalars().all()]


@router.post("/recipes", response_model=AutoPkgRecipeRead)
async def create_recipe(
    data: AutoPkgRecipeCreate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    existing = await session.execute(
        select(AutoPkgRecipe).where(AutoPkgRecipe.identifier == data.identifier)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Recipe already exists")

    recipe = AutoPkgRecipe(
        **data.model_dump(exclude={"github_repo", "recipe_path"})
    )
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
    query = (
        select(AutoPkgRecipe)
        .where(AutoPkgRecipe.is_override.is_(True))
        .order_by(AutoPkgRecipe.name)
    )
    if status:
        query = query.where(AutoPkgRecipe.trust_status == status)
    result = await session.execute(query)
    return [AutoPkgRecipeRead.model_validate(r) for r in result.scalars().all()]


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

    recipe.trust_verified_at = datetime.now(timezone.utc)

    if result.status == "verified":
        recipe.trust_status = "verified"
        recipe.trust_diff = None
    elif result.status == "failed":
        recipe.trust_status = "pending_approval"
        recipe.trust_diff = result.diff

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
        recipe.trust_diff = None

    await create_audit_entry(
        session,
        action="verify_trust",
        entity_type="autopkg_recipe",
        entity_id=str(recipe_id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        notes=f"Trust status: {result.status}"
        + (f" - {result.error}" if result.error else ""),
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
            detail="Could not resolve parent recipes from GitHub. "
            "Check that the parent recipe identifier is correct.",
        )

    old_trust = recipe.trust_info
    recipe.trust_info = new_trust
    recipe.trust_status = "verified"
    recipe.trust_diff = None
    recipe.trust_verified_at = datetime.now(timezone.utc)
    recipe.trust_approved_by = user.email if user else "system"
    recipe.trust_approved_at = datetime.now(timezone.utc)

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
    now = datetime.now(timezone.utc)

    if data.approved:
        change_request.status = "approved"
        change_request.reviewed_by = reviewer
        change_request.reviewed_at = now
        change_request.comment = data.comment

        recipe.trust_info = change_request.new_trust_info
        recipe.trust_status = "verified"
        recipe.trust_diff = None
        recipe.trust_approved_by = reviewer
        recipe.trust_approved_at = now
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
            recipe.trust_verified_at = datetime.now(timezone.utc)

            if verification.status == "verified":
                recipe.trust_status = "verified"
                recipe.trust_diff = None
                summary["verified"] += 1
            elif verification.status == "failed":
                recipe.trust_status = "pending_approval"
                recipe.trust_diff = verification.diff

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
        await session.execute(
            select(GitHubRecipeRepo).where(GitHubRecipeRepo.full_name == full_name)
        )
    ).scalar_one_or_none()
    if not repo:
        raise HTTPException(
            status_code=404, detail="Repo not in cache. Sync repos first."
        )
    count = await sync_repo_recipes_to_cache(session, repo)
    return {"repo": full_name, "recipes_synced": count}


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

    override_plist = {
        "Identifier": override_info["identifier"],
        "ParentRecipe": override_info["parent_recipe"],
        "Input": input_variables or {},
    }
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
    override_plist["ParentRecipeTrustInfo"] = plist_trust

    clone_url = f"https://github.com/{data.github_repo}.git"
    result = await session.execute(
        select(AutoPkgRepo).where(AutoPkgRepo.url == clone_url)
    )
    repo = result.scalar_one_or_none()
    if not repo:
        repo = AutoPkgRepo(
            url=clone_url,
            name=data.github_repo,
        )
        session.add(repo)
        await session.flush()

    payload = {
        "identifier": override_info["identifier"],
        "name": data.name,
        "parent_recipe": override_info["parent_recipe"],
        "input_variables": input_variables,
        "trust_info": trust_info,
        "override_data": override_plist,
        "repo_id": repo.id,
        "is_override": True,
        "is_enabled": data.is_enabled,
        "auto_promote": data.auto_promote,
        "target_catalogs": data.target_catalogs,
        "trust_status": "verified",
    }

    existing = await session.execute(
        select(AutoPkgRecipe).where(AutoPkgRecipe.identifier == payload["identifier"])
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Recipe override already exists")

    recipe = AutoPkgRecipe(**payload)
    session.add(recipe)

    audit_snapshot = {**payload, "repo_id": str(payload["repo_id"])}
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
    Uses the repo relationship on each recipe as the primary source,
    falling back to inference from trust_info for legacy recipes.
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
        if recipe.repo:
            all_repos.add(recipe.repo.name)
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

    result.approval_status = (
        ApprovalStatus.approved if data.approved else ApprovalStatus.rejected
    )
    result.approved_by = user.email if user else "anonymous"
    result.approved_at = datetime.now(timezone.utc)
    result.approval_comment = data.comment

    await create_audit_entry(
        session,
        action="approve" if data.approved else "reject",
        entity_type="autopkg_run_result",
        entity_id=str(result_id),
        entity_name=result.recipe_name,
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
