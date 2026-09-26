#!/bin/bash

#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Terminate on error
set -e

# Prepare variables for later use
images=()
# The images will be pushed to the GitHub container registry
repobase="${REPOBASE:-ghcr.io/tebbiworld}"
# Configure the image name
reponame="windeploy"

#
# Samba runtime: writes GPOs over LDAP and SMB (tool/Containerfile). The
# module image pins it with the same tag, so module and runtime always
# come from the same build.
#
tool_ctx=$(mktemp -d)
trap 'rm -rf "${tool_ctx}"' EXIT
cp tool/Containerfile tool/gpowrite.py imageroot/pypkg/gpogen.py imageroot/pypkg/wingetindex.py "${tool_ctx}/"
buildah build --layers --tag "${repobase}/${reponame}-samba" "${tool_ctx}"
images+=("${repobase}/${reponame}-samba")

# Create a new empty container image
container=$(buildah from scratch)

# Reuse existing nodebuilder-windeploy container, to speed up builds
if ! buildah containers --format "{{.ContainerName}}" | grep -q nodebuilder-windeploy; then
    echo "Pulling NodeJS runtime..."
    buildah from --name nodebuilder-windeploy -v "${PWD}:/usr/src:Z" docker.io/library/node:24.16.0-slim
fi

echo "Build static UI files with node..."
buildah run \
    --workingdir=/usr/src/ui \
    --env="NODE_OPTIONS=--openssl-legacy-provider" \
    nodebuilder-windeploy \
    sh -c "yarn install && yarn build"

# Add imageroot and the compiled UI to the container image
buildah add "${container}" imageroot /imageroot
buildah add "${container}" ui/dist /ui
# Rootless module without TCP ports or routes: the UI talks to it through
# actions only. The Samba runtime image is pre-pulled by the node agent and
# exposed to the actions as ${WINDEPLOY_SAMBA_IMAGE}.
buildah config --entrypoint=/ \
    --label="org.nethserver.rootfull=0" \
    --label="org.nethserver.images=${repobase}/${reponame}-samba:${IMAGETAG:-latest}" \
    "${container}"
# Commit the image
buildah commit "${container}" "${repobase}/${reponame}"

# Append the image URL to the images array
images+=("${repobase}/${reponame}")

#
# Setup CI when pushing to Github.
# Warning! docker::// protocol expects lowercase letters (,,)
if [[ -n "${CI}" ]]; then
    # Set output value for Github Actions
    printf "images=%s\n" "${images[*],,}" >> "${GITHUB_OUTPUT}"
else
    # Just print info for manual push
    printf "Publish the images with:\n\n"
    for image in "${images[@],,}"; do printf "  buildah push %s docker://%s:%s\n" "${image}" "${image}" "${IMAGETAG:-latest}" ; done
    printf "\n"
fi
