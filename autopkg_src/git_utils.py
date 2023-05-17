import contextlib
import logging
import os
import shutil
from pathlib import Path
from urllib.parse import urljoin

import git
import requests


def create_pull_request(repo, title, body, head, base="main"):
    remote_url = repo.remotes.origin.url
    parts = remote_url.split("/")
    organization = parts[-2].replace(".git", "")
    name = parts[-1]
    payload = {
        "title": title,
        "body": body,
        "head": head,
        "base": base,
    }
    url = urljoin(f"https://api.github.com/repos/{organization}/{name}/", "pulls")
    headers = {
        "Authorization": f"token {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.json()


def worktree_commit(repo, branch, file_changes, commit_message):
    """Commit changes to a worktree and push to origin"""
    logging.info(f"Adding worktree for {branch}")
    repo.git.worktree("add", branch, "-b", branch)
    worktree_path = Path(repo.working_dir) / branch
    worktree_repo = git.Repo(worktree_path)
    worktree_remote = worktree_repo.remotes[0].name
    worktree_repo.git.fetch()
    if branch in repo.git.branch("--list", "-r"):
        worktree_repo.git.push(worktree_remote, "--delete", branch)
    logging.info(f"Committing {file_changes} to {branch}")
    for file_change in file_changes:
        src_path = Path(repo.working_dir) / file_change
        dest_path = worktree_path / file_change
        logging.info(f"Copying {src_path} to {dest_path}")
        shutil.copy(src_path, dest_path)
        worktree_repo.index.add([dest_path])
    worktree_repo.index.commit(commit_message)
    worktree_repo.git.push("--set-upstream", worktree_remote, branch)
    with contextlib.suppress(Exception):
        repo.git.worktree("remove", branch, "-f")
