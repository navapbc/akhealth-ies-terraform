# Azure Container Registry

- **Resource provider**: `Microsoft.ContainerRegistry`

## Purpose in the IEP

Azure Container Registry stores the container images used by App Services and Function Apps in the Microsoft.Web hosting estate. It is the central artifact repository for the platform's container-based deployment model.

## Region considerations

- Region selection: matters strongly because the registry is a regional dependency for image storage and pull performance. West US 2 is the likely primary registry region, and West Central US should be evaluated as a secondary replication or standby location for DR.
- Availability zones: are not the primary concernfor this service, but regional resiliency and image availability are still important.
- Paired-region and DR considerations: are important because App Services and Function Apps hosted from registry images depend on image availability during deployment and recovery.
- Service by service regional validation: is required for SKU support, private networking, geo-replication options, and regional capacity expectations.
- Feature parity: should not be assumed between West US 2 and West Central US, particularly for replication features and private networking.

## Design considerations

- Decide whether a single primary registry is sufficient or whether regional replication is required for DR.
- Use private networking services so runtime image pulls stay private.
- Plan image naming, tagging, retention, and promotion practices.
- Ensure Microsoft.Web workloads (app services) can auth to pull images without using shared credentials/using RBAC.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- App Service / Web App / API App
- Azure Functions / Function App
- App Service Environment
- Managed Identity
- Private Endpoints
- Key Vault

## Open questions

- Is one primary registry sufficient, or is West Central US replication required?
- What image promotion strategy will separate build, test, and production artifacts?
- Which identities will be authorized to pull images at runtime?
- Will public network access be disabled for the registry?
- How long must old images be retained for rollback and audit needs?

## Relevant links

- [Microsoft Learn: Azure Container Registry introduction](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-intro)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes

- Because the platform expects Microsoft.Web workloads to run from ACR images, registry availability directly affects both release safety and DR readiness.
