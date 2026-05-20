# Event Grid

- **Resource provider**: `Microsoft.EventGrid`

## Purpose in the IEP

Event Grid provides lightweight event routing/reaction integration. It is useful when the platform needs to respond to resource or application events without adding a queue type configuration for every operation.

## Region considerations

- Region selection: matters because Event Grid topics and subscriptions have regional behavior and service-specific delivery paths. West US 2 is the likely primary region, and West Central US should be evaluated if event-driven DR operation is required.
- Availability zones: are not usually the primary planning lever for Event Grid itself, but regional service continuity still needs consideration.
- Paired-region and DR considerations: are relevant because event sources, subscribers, dead-letter targets, and replay assumptions may differ across regions.
- Instance by instance regional validation is required for supported event sources, private access patterns, delivery features, and subscription behaviors in both regions.
- Feature parity: should not be assumed between West US 2 and West Central US, especially for newer event source integrations.

## Design considerations

- Decide which workflows need event notifications versus durable actual queues.
- Plan private or controlled endpoint exposure for event delivery where required.
- Validate how regional failover affects publishers, subscribers, and dead-letter destinations.
- Keep event configurations stable enough for long term integration considerations.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- Azure Functions / Function App
- App Service / Web App / API App
- Storage Account
- Service Bus
- Azure Automation / Runbooks
- Azure Monitor alerting / monitor resources

## Open questions

- When should Event Grid be used instead of Service Bus?
- What dead-letter destinations and replay expectations are required?
- Do West US 2 and West Central US need separate event topologies for DR?

## Relevant links

- [Microsoft Learn: Azure Event Grid overview](https://learn.microsoft.com/en-us/azure/event-grid/overview)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes

- Event Grid is probably best used for notification and such while Service Bus is expected to handle durable work queues.
