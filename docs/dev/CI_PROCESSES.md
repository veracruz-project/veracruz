# Updating CI Image

The process for updating the Docker image used in CI is:

1) Create a branch with all the changes needed for the update (typically in `docker/` folder). The branch needs to be pushed to the `veracruz` repository (not a fork) to have the permissions to the container registry.

2) Increase the `VERSION` in `docker/Makefile`. The format is typically based on year and month (e.g. `v22.12` for December 2022), but could include letters if multiple updates happen within the same month (e.g. `v22.12a`, `v22.12b`, etc.).

3) Once all changes in the branch are pushed to the repository, run `Build Docker Image` workflow in Github Actions. If the workflow is successful, the new version of the Docker image should appear [project packages](https://github.com/veracruz-project/veracruz/pkgs/container/veracruz%2Fci) and the Github Actions logs should contain the command signing the Docker image with its digest:

```
COSIGN_EXPERIMENTAL=true cosign sign -y \
	ghcr.io/veracruz-project/veracruzci@sha256:b5eb834cd58c69e6acc19b1b19c6345a020ad2ad090cdab3bc9f7d5d48fb00ba
```

4) The Digest of the Docker image in the project packages registry should match the value found in the logs (e.g. `sha256:b5eb834cd58c69e6acc19b1b19c6345a020ad2ad090cdab3bc9f7d5d48fb00ba`). This value should now be used to edit `.github/workflows/main.yml` and replace the value of the previous image. This change should be commited and pushed to the branch.

5) A pull request for the branch should now be created. This will trigger the execution of CI using the new Docker image.

6) If CI is successful and the pull request is acceptable, then the pull should be merged and the branch deleted. The commit from which the image was built should be preserved and be part of branch that is merged. If CI is not successful and changes need to be made to the Docker files, the commit modifying `github/workflows/main.yml` should be backed out, and the process should resume from step 3.
