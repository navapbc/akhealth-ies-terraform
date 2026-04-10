data "azurerm_client_config" "current" {}

locals {
  region_abbreviations = {
    eastus         = "eus"
    eastus2        = "eus2"
    westus         = "wus"
    westus2        = "wus2"
    westus3        = "wus3"
    centralus      = "cus"
    northcentralus = "ncus"
    southcentralus = "scus"
    westcentralus  = "wcus"
    global         = "global"
  }

  normalized_workload_description = var.workload_description == null ? null : (
    trimspace(var.workload_description) == "" ? null : trimspace(var.workload_description)
  )
  region_abbreviation = local.region_abbreviations[var.location]
  workload_segment    = local.normalized_workload_description == null ? "" : "-${local.normalized_workload_description}"

  resource_group_name = substr(
    "rg-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}",
    0,
    90
  )

  existing_log_analytics_workspace_id   = var.existing_log_analytics_id == null ? "" : trimspace(var.existing_log_analytics_id)
  private_networking_enabled            = var.deploy_private_networking && trimspace(var.spoke_network_config.privateEndpointSubnetAddressSpace) != ""
  web_app_private_networking_enabled    = local.private_networking_enabled && !var.deploy_ase_v3
  postgresql_enabled                    = var.deploy_postgresql
  postgresql_private_networking_enabled = local.postgresql_enabled && var.deploy_private_networking
  postgresql_private_access_enabled     = local.postgresql_enabled && var.postgresql_config.privateAccessMode == "delegatedSubnet"
  use_existing_app_service_plan         = trimspace(var.service_plan_config.existingPlanId) != ""
  deploy_app_service_plan               = !local.use_existing_app_service_plan
  use_front_door_ingress                = var.spoke_network_config.ingressOption == "frontDoor"
  use_application_gateway_ingress       = var.spoke_network_config.ingressOption == "applicationGateway"
  resolved_log_analytics_workspace_id   = local.existing_log_analytics_workspace_id != "" ? var.existing_log_analytics_id : module.log_analytics_workspace[0].resource_id
  resolved_app_service_plan_resource_id = local.use_existing_app_service_plan ? var.service_plan_config.existingPlanId : module.app_service_plan[0].resource_id
  postgresql_role_assignments = concat(var.postgresql_config.roleAssignments, var.postgresql_config.grantAppServiceIdentityReaderRole ? [{
    key                = "app-service-reader"
    roleDefinitionName = "Reader"
    principalId        = module.web_app.system_assigned_mi_principal_id
    principalType      = "ServicePrincipal"
    description        = "Allows the web app system-assigned identity to read PostgreSQL flexible server resource metadata."
  }] : [])
  spoke_private_dns_zone_links = [
    {
      name                     = module.network.vnet_spoke_name
      virtualNetworkResourceId = module.network.vnet_spoke_resource_id
      registrationEnabled      = false
    }
  ]
  optional_hub_private_dns_zone_link = var.spoke_network_config.hubPeeringConfig == null ? [] : [
    {
      name                     = var.spoke_network_config.hubPeeringConfig.virtualNetworkName
      virtualNetworkResourceId = var.spoke_network_config.hubPeeringConfig.virtualNetworkResourceId
      registrationEnabled      = false
    }
  ]
  private_dns_zone_virtual_network_links = concat(local.spoke_private_dns_zone_links, local.optional_hub_private_dns_zone_link)
}
