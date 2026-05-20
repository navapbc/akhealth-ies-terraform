# Private DNS zone / private DNS networking objects

- **Resource provider**: `Microsoft.Network`

## Purpose in the IEP

Private DNS networking objects provide the internal name-resolution layer for private endpoints and other private service access patterns.

## Region considerations

- Region selection matters: indirectly because private DNS zones are typically global in control plane terms but are consumed through regional virtual networks and private access designs. West US 2 and West Central US both need to be accounted for in the DNS linking strategy.
- Availability zones: are not a direct concern for private DNS zones.
- Paired region and DR considerations: are important because name resolution often breaks failover plans before compute or data services do.
- Service by service regional validation: is required for private endpoint DNS patterns, service-specific naming rules, and how secondary-region resources should resolve.
- Feature parity: should not be assumed between primary and secondary regions for the services that depend on private DNS resolution, even if the DNS objects themselves are not region-bound in the same way.

## Design considerations

- Decide whether private DNS will be centrally managed (likely) or segmented by service boundary.
- Plan zone linking across both West US 2 and West Central US virtual networks.
- Validate DNS requirements for every private endpoint enabled service before deployment.
- Keep DNS ownership and change control clear because it affects many teams at once.
- Avoid additional DNS complexity if only a small number of private endpoints are in use initially.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- Virtual Network
- Private Endpoints
- Key Vault
- Storage Account
- Azure Container Registry
- Service Bus

## Open questions

- Which services in scope need private DNS records immediately?
- How will DNS zones be linked across West US 2 and West Central US virtual networks?
- Who owns private DNS changes and incident response?
- Are there any naming conflicts with existing enterprise DNS standards?

## Relevant links

- [Microsoft Learn: Azure Private DNS overview](https://learn.microsoft.com/en-us/azure/dns/private-dns-overview)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes
