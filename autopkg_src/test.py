import os


import git


MUNKI_REPO_DIR = os.getenv("GITHUB_WORKSPACE", "./")
AUTOPKG_DIR = os.path.join(MUNKI_REPO_DIR, "autopkg_src")
RECIPE_TO_RUN = os.environ.get("RECIPE", None)
MUNKI_REPO = git.Repo(MUNKI_REPO_DIR)


def worktree_add(branch):
    """Add a worktree for the branch and return the repo object"""
    MUNKI_REPO.git.worktree("add", branch, "-b", branch)
    return git.Repo(os.path.join(MUNKI_REPO.working_dir, branch))


def worktree_commit(recipe):
    worktree_repo = worktree_add(recipe)
    return worktree_repo


def worktree_remove(branch):
    MUNKI_REPO.git.worktree("remove", branch, "-f")
    MUNKI_REPO.git.branch("-D", branch)


def main():
    # print("Hello from main")
    # print(f"RECIPE_TO_RUN: {RECIPE_TO_RUN}")
    # print(f"MUNKI_REPO_DIR: {MUNKI_REPO_DIR}")
    # print(f"AUTOPKG_DIR: {AUTOPKG_DIR}")
    # print(f"MUNKI_REPO: {MUNKI_REPO}")
    # print(f"MUNKI_REPO_DIR: {MUNKI_REPO_DIR}")

    wt = worktree_commit("test_branch")
    print(dir(MUNKI_REPO.remotes.origin))
    print(MUNKI_REPO.head)
    print(MUNKI_REPO.remotes.origin.url)
    print(MUNKI_REPO.branches)
    print(MUNKI_REPO.has_separate_working_tree)
    print(wt.working_dir)
    print(wt.working_tree_dir)
    worktree_remove("test_branch")
    shutil.copy()


if __name__ == "__main__":
    main()
