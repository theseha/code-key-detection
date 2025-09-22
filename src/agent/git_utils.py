import os
import shutil
from git import Repo

def clone_repo(repo_url: str, workdir: str, branch: str = "main") -> str:
    repo_name = os.path.splitext(os.path.basename(repo_url))[0]
    local_dir = os.path.join(workdir, repo_name)
    if os.path.isdir(local_dir):
        shutil.rmtree(local_dir)
    print(f"[INFO] Cloning {repo_url} (branch: {branch}) into {local_dir}")
    Repo.clone_from(repo_url, local_dir, branch=branch, depth=1)
    return local_dir
