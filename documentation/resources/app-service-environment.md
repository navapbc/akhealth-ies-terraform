# App Service Environment

- **Resource provider**: `Microsoft.Web`

## Purpose in the IEP

The App Service Environment provides the isolated, network-integrated hosting boundary for web apps and function apps. They allow Microsoft.Web workloads to run inside a controlled virtual network perimeter.

## Region considerations

- Region choice: matters because the App Service Environment is the regional hosting boundary for the application platform. West US 2 is the likely primary region, and West Central US would require its own app service environment footprint if DR hosting is expected.
- Availability zones: may be relevant depending on supported app service environment generation, deployment model, and regional capability, so zone assumptions should be validated explicitly.
- Paired-region and DR considerations: are significant because application failover cannot rely on the primary app service environment; a separate secondary-region hosting environment is typically needed.
- Service by service regional validation: is required for app service environment support, capacity, subnet requirements, zone options, and dependent Microsoft.Web capabilities in both target regions.
- Feature parity: should not be assumed between West US 2 and West Central US for app service environment availability, quotas, or related hosting, etc... .


## Design considerations

- Reserve a dedicated subnet with sufficient capacity for scaling.
- Decide how many app service environment instances are required by environment, workload class, or region.
- Plan ingress, egress, and DNS behavior together with Application Gateway and private networking.
- Validate how app service environment sizing, scaling, and cost align with the expected application estate.
- Design DR as a separate regional hosting capability rather than as an implied platform feature.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- Virtual Network
- Subnets
- App Service Plan
- App Service / Web App / API App
- Azure Functions / Function App
- Azure Container Registry

## Open questions

- How many app service environment instances are required across environments and regions?
- What subnet size is needed for initial deployment and future platform growth?
- Which workloads must run inside the app service environment on day one versus later phapp service environments?
- Is a warm or active secondary app service environment required in West Central US for DR objectives?
- What ingress and egress controls are mandatory for app service environment-hosted workloads?

## Relevant links

- [Microsoft Learn: App Service Environment overview](https://learn.microsoft.com/en-us/azure/app-service/environment/overview)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes

- The platform description provided assumes app service environment/hosting rather than public multi-tenant App Service, so app service environment sizing and network design must be particularly considered.
