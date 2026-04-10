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

  region_abbreviation = lookup(local.region_abbreviations, var.location, replace(var.location, " ", ""))
  workload_segment    = trimspace(var.workload_description) == "" ? "" : "-${var.workload_description}"

  resource_group_name = substr(
    "rg-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}",
    0,
    90
  )

  private_networking_enabled            = var.deploy_private_networking && try(var.spoke_network_config.privateEndpointSubnetAddressSpace, "") != ""
  web_app_private_networking_enabled    = local.private_networking_enabled && !var.deploy_ase_v3
  postgresql_enabled                    = var.deploy_postgresql
  postgresql_private_networking_enabled = local.postgresql_enabled && var.deploy_private_networking
  postgresql_private_access_enabled     = local.postgresql_enabled && try(var.postgresql_config.privateAccessMode, "none") == "delegatedSubnet"
  use_existing_app_service_plan         = trimspace(try(var.service_plan_config.existingPlanId, "") == null ? "" : try(var.service_plan_config.existingPlanId, "")) != ""
  deploy_app_service_plan               = !local.use_existing_app_service_plan
  use_front_door_ingress                = try(var.spoke_network_config.ingressOption, "none") == "frontDoor"
  use_application_gateway_ingress       = try(var.spoke_network_config.ingressOption, "none") == "applicationGateway"
  resolved_log_analytics_workspace_id   = trimspace(var.existing_log_analytics_id == null ? "" : var.existing_log_analytics_id) != "" ? var.existing_log_analytics_id : module.log_analytics_workspace[0].resource_id
  resolved_app_service_plan_resource_id = local.use_existing_app_service_plan ? var.service_plan_config.existingPlanId : module.app_service_plan[0].resource_id
  postgresql_role_assignments = concat(try(var.postgresql_config.roleAssignments, []), try(var.postgresql_config.grantAppServiceIdentityReaderRole, false) ? [{
    roleDefinitionIdOrName = "Reader"
    principalId            = module.web_app.system_assigned_mi_principal_id
    principalType          = "ServicePrincipal"
    description            = "Allows the web app system-assigned identity to read PostgreSQL flexible server resource metadata."
  }] : [])
  spoke_private_dns_zone_links = [
    {
      name                     = module.network.vnet_spoke_name
      virtualNetworkResourceId = module.network.vnet_spoke_resource_id
      registrationEnabled      = false
    }
  ]
  optional_hub_private_dns_zone_link = try(var.spoke_network_config.hubPeeringConfig, null) == null ? [] : [
    {
      name                     = var.spoke_network_config.hubPeeringConfig.virtualNetworkName
      virtualNetworkResourceId = var.spoke_network_config.hubPeeringConfig.virtualNetworkResourceId
      registrationEnabled      = false
    }
  ]
  postgresql_private_dns_zone_links = concat(local.spoke_private_dns_zone_links, local.optional_hub_private_dns_zone_link)
}
