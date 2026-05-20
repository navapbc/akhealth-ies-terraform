# Azure Database for PostgreSQL Flexible Server

- **Resource provider**: `Microsoft.DBforPostgreSQL`

## Purpose in the IEP

Azure Database for PostgreSQL Flexible Server provides the primary relational database platform the IEP workload.

## Region considerations

- Region selection matters strongly because the database is a regional stateful dependency. West US 2 is the likely primary database region, and West Central US should be evaluated deliberately for secondary or DR data strategy.
- Availability zones should be considered carefully as Flexible Server offers HA patterns that may depend on zone placement and regional support.
- Paired region and DR considerations are significant because backups, replicas, failover, and recovery point expectations must be considered specifically.
- Regional validation is required for HA modes, private access patterns, maintenance options, storage performance, and replica capabilities in both regions.
- Feature parity should not be assumed between West US 2 and West Central US, especially for high availability and regional replica features.

## Design considerations

- Private access config/subnet arrangement.
- Validate storage sizing, IOPS, compute scaling, and maintenance windows against workload needs.
- Plan HA and DR separately, including backup retention, replica strategy, and failover expectations.
- Use managed identities/entra auth where configs support it.
- Confirm whether all intended workloads fit a shared PostgreSQL platform or need separate databases/server instances.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- Virtual Network
- Subnets (dedicated)
- App Service / Web App / API App
- Azure Functions / Function App
- Managed Identity
- Key Vault

## Open questions

- What HA and DR objectives are required for databases in West US 2 and West Central US?
- Which private networking model will be used for database access?
- How will schema change management and database ownership be handled?
- Are there workloads that need separate database instances for security or performance isolation?

## Relevant links

- [Microsoft Learn: Azure Database for PostgreSQL Flexible Server overview](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/overview)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes
