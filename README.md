# akhealth-ies-terraform
Backend setup script

az group create \
  --name rg-iep-eus-dev-operations-01 \
  --location eastus2

az storage account create \
  --name stiepeusdevtf001 \
  --resource-group rg-iep-eus-dev-operations-01 \
  --location eastus2 \
  --sku Standard_LRS \
  --kind StorageV2 \
  --allow-blob-public-access false \
  --min-tls-version TLS1_2

az storage container create \
  --name stc-iep-eus-dev-tfstate-001 \
  --account-name stiepeusdevtf001 \
  --auth-mode login

## Usage

```bash
terraform init
terraform plan -var-file=environments/main.dev.tfvars
```

resourceAbbreviation-systemAbbreviation-regionAbbreviation-environmentAbbreviation-workloadDescription-subWorkloadDescription-instanceNumber

## Resource Group Names Examples

rg-iep-eus-dev-network-01
rg-iep-eus-dev-network-edge-01
rg-iep-eus-dev-network-private-01
rg-iep-eus-dev-hosting-01
rg-iep-eus-dev-data-01
rg-iep-eus-dev-operations-01

# Naming scheme

Resource names should flow and be readable from broad resource type to specific instance:

1. resource abbreviation
2. system abbreviation
3. region abbeviation
4. environment abbreviation
5. workload description (when it is relevant)
6. instance number

resourceAbbreviation-systemAbbreviation-regionAbbreviation-environmentAbbreviation-workloadDescription-instanceNumber

Resource Abbreviation - https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations
System Abbreviation - Abbreviation representing the authorized system the resouce belongs to
Region Abbreviation - WestUS/wus, WestUS2/wus
Environment Abbreviation - Development/dev, Test/tst, Staging/stg, User Acceptance Testing/uat, Production/prd 
Workload Description (optional) - A short description of the workload the resource is supporting (only when it adds meaning to the name)
Instance Number - to denote the instance number for uniqueness

If naming is very restictive you may remove dashes. You may also remove region abbeviation only if you must do so to comply with naming length restrictions. You may also remove a 0 from the instance numbering (001 to 01) only if you must do so. You would handle these accomodations in the resource specific module when it is assembling the resource name.

When workloadDescription is not defined, the segment should be not included. It should not leave an empty segment or a double dash.

example for this template set: kv-iep-wus-dev-001, app-iep-eus-dev-tasks-001

## Naming implementation

This template should keep naming consistent globally, while keeping final name creation close to the resource that owns the name.

- Shared naming components should be declared explicitly in .bicepparams.
- Shared naming components should flow through main into the modules that need them.
- Resource abbreviations should stay local to the module that creates that specific resource.
- Region abbreviation uses a shared map (because all resources are defined with a more fixed set of regions)
- Resource specific naming schemes should be handled in the module for that resource.

This keeps naming readable and predictable without adding an extra abstraction layer that users have to mentally work through.

## Repo-Local Abbreviations

Considerations: Use Microsoft CAF abbreviations where Microsoft publishes one. Microsoft mixes abbreviations for the Microsoft.CDN provider between cdnp, cdne, fde, and afd. They use fde to convery frontdoor product vs where i would prefer to be technically honest and convery the actual resource type (cdn). But, for end user legibility purposes, afd and fd are sufficiently communicative. 


For resource types that don't have an official CAF abbreviation, this repo uses the following local conventions:

- fdsecp for Microsoft.Cdn/profiles/securityPolicies
- fder for Microsoft.Cdn/profiles/afdEndpoints/routes
- fdog for Microsoft.Cdn/profiles/originGroups
- fdorg for Microsoft.Cdn/profiles/originGroups/origins
- fdrset for Microsoft.Cdn/profiles/ruleSets
- fdrul for Microsoft.Cdn/profiles/ruleSets/rules
- fdcdom for Microsoft.Cdn/profiles/customDomains
- fdsecr for Microsoft.Cdn/profiles/secrets


## Resource Groups and Naming

For resource groups, we will break the scheme just a small bit, because resource groups are moreso containers and less dedicated resources.

resourceAbbreviation-systemAbbreviation-regionAbbreviation-environmentAbbreviation-workloadDescription-subWorkloadDescription-instanceNumber

## Resource Group Names Examples

rg-iep-eus-dev-network-01
rg-iep-eus-dev-network-edge-01
rg-iep-eus-dev-network-private-01
rg-iep-eus-dev-hosting-01
rg-iep-eus-dev-data-01
rg-iep-eus-dev-operations-01