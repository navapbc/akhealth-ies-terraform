# Storage Account

- **Resource provider**: `Microsoft.Storage`

## Purpose in the IEP

Storage Account provides object and service storage for applications, functions, diagnostics, and integration workflows.

## Region considerations

- Region selection: matters strongly because storage accounts are regional and frequently used by multiple services. West US 2 is the likely primary region, and West Central US should be evaluated for replication or secondary storage needs tied to DR.
- Availability zones are relevant: where zone redundancy options are available and appropriate for the workload.
- Paired region and DR considerations: are significant because redundancy choices such as LRS, ZRS, GRS, and related options materially affect recovery behavior.
- Service by service regional validation: is required for redundancy SKU availability, private endpoint behavior, and specialized storage features in both regions.
- Feature parity: should not be assumed between West US 2 and West Central US for redundancy options, performance tiers, or network capabilities.

## Design considerations

- Separate storage accounts by workload sensitivity, lifecycle, or performance needs when necessary.
- Choose redundancy and replication strategy based on DR expectations, not only cost.
- Prefer private access and disable unnecessary public network exposure.
- Define naming, lifecycle, and retention patterns early because storage sprawl is common.
- Validate how West Central US DR will use replicated versus region-local storage.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- Azure Functions / Function App
- Azure Data Factory
- Event Grid
- Private Endpoints
- Azure Monitor alerting / monitor resources
- Key Vault

## Open questions

- Define storage use cases.
- Should application data, diagnostics, and integration artifacts be separated into different accounts?
- What redundancy option is appropriate for each storage workload?
- How will West Central US consume or recover required storage data during DR?

## Relevant links

- [Microsoft Learn: Azure Storage account overview](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes
