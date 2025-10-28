#
# Copyright © contributors to CloudNativePG, established as
# CloudNativePG a Series of LF Projects, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#

variable "environment" {
  default = "testing"
  validation {
    condition = contains(["testing", "production"], environment)
    error_message = "environment must be either testing or production"
  }
}

variable "registry" {
  default = "localhost:5000"
}

variable "insecure" {
  default = "false"
}

variable "latest" {
  default = "false"
}

variable "tag" {
  default = "dev"
}

variable "buildVersion" {
  default = "dev"
}

variable "revision" {
  default = ""
}

suffix = (environment == "testing") ? "-testing" : ""

title = "PostgreSQL OAuth validator module for Keycloak"
description = "This module enables PostgreSQL to delegate authorization decisions to Keycloak using OAuth tokens, leveraging Keycloak Authorization Services for fine-grained, token-based access control."
authors = "The CloudNativePG Contributors"
url = "https://github.com/cloudnative-pg/"
documentation = "https://cloudnative-pg.io/"
license = "Apache-2.0"
now = timestamp()


# renovate: datasource=docker
baseImage = "ghcr.io/cloudnative-pg/postgresql:18-standard-trixie"

target "default" {
  matrix = {
    distro = [
      "base",
    ]
  }

  name = "${distro}"
  platforms = ["linux/amd64", "linux/arm64"]
  tags = [
    "${registry}/postgres-keycloak-oauth-validator${suffix}:${tag}",
    latest("${registry}/postgres-keycloak-oauth-validator${suffix}", "${latest}"),
  ]

  dockerfile = "docker/Dockerfile"
  context    = "."

  args = {
    BASE = "${baseImage}"
  }

  output = [
    "type=image,registry.insecure=${insecure}",
  ]

  attest = [
    "type=provenance,mode=max",
    "type=sbom"
  ]
  annotations = [
    "index,manifest:org.opencontainers.image.created=${now}",
    "index,manifest:org.opencontainers.image.url=${url}",
    "index,manifest:org.opencontainers.image.source=${url}",
    "index,manifest:org.opencontainers.image.version=${buildVersion}",
    "index,manifest:org.opencontainers.image.revision=${revision}",
    "index,manifest:org.opencontainers.image.vendor=${authors}",
    "index,manifest:org.opencontainers.image.title=${title}",
    "index,manifest:org.opencontainers.image.description=${description}",
    "index,manifest:org.opencontainers.image.documentation=${documentation}",
    "index,manifest:org.opencontainers.image.authors=${authors}",
    "index,manifest:org.opencontainers.image.licenses=${license}",
    "index,manifest:org.opencontainers.image.base.name=",
    "index,manifest:org.opencontainers.image.base.digest=",
  ]
  labels = {
    "org.opencontainers.image.created"       = "${now}",
    "org.opencontainers.image.url"           = "${url}",
    "org.opencontainers.image.source"        = "${url}",
    "org.opencontainers.image.version"       = "${buildVersion}",
    "org.opencontainers.image.revision"      = "${revision}",
    "org.opencontainers.image.vendor"        = "${authors}",
    "org.opencontainers.image.title"         = "${title}",
    "org.opencontainers.image.description"   = "${description}",
    "org.opencontainers.image.documentation" = "${documentation}",
    "org.opencontainers.image.authors"       = "${authors}",
    "org.opencontainers.image.licenses"      = "${license}",
    "org.opencontainers.image.base.name"     = "",
    "org.opencontainers.image.base.digest"   = "",
    "name"                                   = "${title}",
    "maintainer"                             = "${authors}",
    "vendor"                                 = "${authors}",
    "version"                                = "${buildVersion}",
    "release"                                = "1",
    "description"                            = "${description}",
    "summary"                                = "${description}",
  }
}

function latest {
  params = [ image, latest ]
  result = (latest == "true") ? "${image}:latest" : ""
}
