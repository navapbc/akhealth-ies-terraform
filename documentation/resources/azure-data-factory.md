# Azure Data Factory

- **Resource provider**: `Microsoft.DataFactory`

## Purpose in the IEP

Azure Data Factory provides managed orchestration for data movement and transformation workflows. It can coordinate batch integrations, scheduled data exchange, and cross-system movement in a platform that is expected to become more integration-heavy over time.

## Region considerations

- Region selection matters as Azure Data Factory is regional and data movement performance often depends on where orchestration and integration components run. West US 2 is the likely primary region, and West Central US should be evaluated if DR orchestration or secondary region processing is required.
- Availability zones are not typically the primary design concern for Data Factory itself, but regional dependency design still matters.
- Paired region and DR considerations require scrutiny because pipelines, triggers, linked services, and runtime connectivity may need specific secondary region planning.
- Service by service regional validation is required for integration runtime capabilities, managed networking options, private access behavior, and connector availability in both regions.
- Feature parity should not be assumed between West US 2 and West Central US for connectors, managed network features, or regional service rollout timing.

## Design considerations

- Decide whether Data Factory is needed for batch orchestration only or for broader integration control.
- Align network connectivity with private-first requirements for data sources and sinks.
- Use managed identity and Key Vault for connection management wherever possible.
- Plan how triggers and runtime behavior should operate during regional failover scenarios.
- Validate which integrations belong in Data Factory versus Function Apps, Logic Apps, or application code.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- Storage Account
- Azure Database for PostgreSQL Flexible Server
- Service Bus
- Key Vault
- Managed Identity
- Azure Monitor alerting / monitor resources

## Open questions

- Which integrations actually require Data Factory vs something simpler?
- Are there data movement workloads that must continue during regional failover?
- What runtime model is required for private data sources and destinations?
- How will secrets and connection metadata be managed across environments?
- Which teams own pipeline development versus platform operations?

## Relevant links

- [Microsoft Learn: Azure Data Factory introduction](https://learn.microsoft.com/en-us/azure/data-factory/introduction)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes

- Data Factory can be a good resource for when integration complexity grows, but it should not own every workflow by default.
