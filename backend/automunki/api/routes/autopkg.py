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
)
from automunki.models.user import User
from automunki.schemas.autopkg import (
    ApprovalRequest,
    AutoPkgRecipeCreate,
    AutoPkgRecipeRead,
    AutoPkgRecipeUpdate,
    AutoPkgRepoCreate,
    AutoPkgRepoRead,
    AutoPkgRunRead,
    GitHubRecipeRepoRead,
    RunResultCreate,
    RunResultRead,
    TriggerRunRequest,
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

    recipe = AutoPkgRecipe(**data.model_dump())
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
    """Add a discovered recipe as an override in the DB. Links to its repo."""
    existing = await session.execute(
        select(AutoPkgRecipe).where(AutoPkgRecipe.identifier == data.identifier)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Recipe override already exists")

    payload = data.model_dump()
    payload["is_override"] = True
    recipe = AutoPkgRecipe(**payload)
    session.add(recipe)

    await create_audit_entry(
        session,
        action="create_override",
        entity_type="autopkg_recipe",
        entity_id=str(recipe.id),
        entity_name=recipe.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        after_snapshot=data.model_dump(),
    )

    await session.commit()
    await session.refresh(recipe)
    return AutoPkgRecipeRead.model_validate(recipe)


# ── Repo management ──────────────────────────────────────────────────────


@router.get("/repos", response_model=list[AutoPkgRepoRead])
async def list_repos(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(AutoPkgRepo).order_by(AutoPkgRepo.name))
    return [AutoPkgRepoRead.model_validate(r) for r in result.scalars().all()]


@router.post("/repos", response_model=AutoPkgRepoRead)
async def add_repo(
    data: AutoPkgRepoCreate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    existing = await session.execute(
        select(AutoPkgRepo).where(AutoPkgRepo.url == data.url)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Repo already exists")

    repo = AutoPkgRepo(**data.model_dump())
    session.add(repo)

    await create_audit_entry(
        session,
        action="add_repo",
        entity_type="autopkg_repo",
        entity_id=str(repo.id),
        entity_name=repo.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )

    await session.commit()
    await session.refresh(repo)
    return AutoPkgRepoRead.model_validate(repo)


@router.delete("/repos/{repo_id}")
async def remove_repo(
    repo_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    repo = await session.get(AutoPkgRepo, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repo not found")

    await create_audit_entry(
        session,
        action="remove_repo",
        entity_type="autopkg_repo",
        entity_id=str(repo_id),
        entity_name=repo.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )

    await session.delete(repo)
    await session.commit()
    return {"message": "Repo removed"}


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
