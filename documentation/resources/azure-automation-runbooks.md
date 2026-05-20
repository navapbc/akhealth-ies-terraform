# Azure Automation / Runbooks

- **Resource provider**: `Microsoft.Automation`

## Purpose in the IEP

Azure Automation and Runbooks provide managed operational automation for various platform and system actions.

## Region considerations

- Region selection: matters because Azure Automation accounts are regional resources. West US 2 is the likely primary operations region, and West Central US should be evaluated if automated remediation or scheduled operations must continue during DR.
- Availability zones: are not typically the main design concern for Automation itself.
- Paired-region and DR considerations: are relevant because runbooks, schedules, credentials, and dependency access may need secondary region attention.
- Service by service regional validation: is needed for networking behavior, managed identity use, module availability, and any regional execution dependencies.
- Feature parity: should not be assumed between West US 2 and West Central US for every automation-related capability or dependency path.

## Design considerations

- Decide which tasks belong in runbooks vs deployment automation or application code.
- Use managed identity and Key Vault rather than embedded credentials.
- Define safe execution boundaries, approvals, and rollback expectations to reduce blast radius.
- Plan whether West Central US needs a mirrored automation footprint for DR operations.
- Ensure runbooks are accessible/funcitonal with private networking components.

## Security considerations

- Stub for potential use later.

## Operational considerations

- Stub for potential use later.

## Dependencies and related resources

- Azure Monitor alerting / monitor resources
- Managed Identity
- Key Vault
- Log Analytics Workspace
- Event Grid
- Service Bus

## Open questions

- Which tasks would be automated?
- Which automations are safe to run unattended versus requiring approval?
- What identity and permission model will runbooks use?
- Does the DR model require runbooks to exist and execute in West Central US?
- Who owns runbook testing, release, and periodic review?

## Relevant links

- [Microsoft Learn: Azure Automation overview](https://learn.microsoft.com/en-us/azure/automation/overview)
- [Microsoft Learn: Azure regions overview](https://learn.microsoft.com/en-us/azure/reliability/regions-overview)
- [Microsoft Learn: Azure availability zones overview](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview)

## Notes