[![Build and Push Docker Image](https://github.com/idp-holy-veriks/service_template/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/idp-holy-veriks/service_template/actions/workflows/docker-publish.yml)

# IDP Service Template
Template to speedup the process of creating multiple services.
## How to setup
Make sure to set the following variables and secrets:
 * variables
   - IMAGE_OWNER - dockerhub name
   - IMAGE_NAME - name of the docker image
 * secrets
   - DOCKERHUB_USERNAME - username of the account that will push the docker image to DockerHub
   - DOCKERHUB_PASSWORD - password/token of the account that will push the docker image to DockerHub

## How it works
For every push on branch main, a new action will be initiated and an image will be built and pushed to DockerHub.
