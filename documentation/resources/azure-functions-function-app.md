# Azure Functions / Function App

- **Resource provider**: `Microsoft.Web`

## Purpose in the IEP

Function Apps provide event/integration specific compute for the platform. Best used for background processing, message handling, scheduled tasks, and workflow steps in an environment with high integration needs expectations over time.

## Region considerations

- Region selection: matters because Function Apps are regional workloads. West US 2 is the likely primary deployment region, and West Central US should be treated as a separate secondary hosting target if DR or regional failover is required.
- Availability zones: not generally handled at the function app resource level.
- Paired-region and DR: considerations are important because event sources, storage dependencies, and trigger behavior need explicit regional design.
- Instance by instance regional validation: is required for Microsoft.Web function capabilities, storage dependencies, networking behavior, and supported hosting patterns in both regions.
- Feature parity between regions: should not be assumed between West US 2 and West Central US, especially where runtime features or scale characteristics vary by region.

## Design considerations

- Align trigger design with Service Bus, Event Grid, Storage, or timer-based configs where applicable.
- Plan cold-start, concurrency, and scaling behavior based on workload criticality.
- Use managed identity/Key Vault/private networking for dependent services.
- Ensure hosting and configuration are compatible with app service environment based/private networking first constraints.
- Consider DR plans carefully so triggers, queues, and event subscriptions do not double process or silently stop during regional failover.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- App Service Environment
- App Service Plan
- Azure Container Registry
- Storage Account
- Service Bus
- Event Grid

## Open questions

- Which workloads are best handled as functions instead of long-running web services?
- Do any function workloads require dedicated compute isolation from other Microsoft.Web apps?
- How will image-based function deployments be promoted and recovered across regions?
- What regional failover behavior is required for event-driven processing in West Central US?

## Relevant links

- [Microsoft Learn: Azure Functions documentation](https://learn.microsoft.com/en-us/azure/azure-functions/)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes