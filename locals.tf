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
  normalized_spoke_network_workload_description = try(var.spoke_network_config.workloadDescription, null) == null ? local.normalized_workload_description : (
    trimspace(var.spoke_network_config.workloadDescription) == "" ? local.normalized_workload_description : trimspace(var.spoke_network_config.workloadDescription)
  )
  normalized_app_service_workload_description = try(var.app_service_config.workloadDescription, null) == null ? local.normalized_workload_description : (
    trimspace(var.app_service_config.workloadDescription) == "" ? local.normalized_workload_description : trimspace(var.app_service_config.workloadDescription)
  )
  normalized_service_plan_workload_description = try(var.service_plan_config.workloadDescription, null) == null ? local.normalized_app_service_workload_description : (
    trimspace(var.service_plan_config.workloadDescription) == "" ? local.normalized_app_service_workload_description : trimspace(var.service_plan_config.workloadDescription)
  )
  workload_segment    = local.normalized_workload_description == null ? "" : "-${local.normalized_workload_description}"
  region_abbreviation = local.region_abbreviations[var.location]

  resource_group_definitions_by_key = {
    for definition in var.resource_group_definitions :
    definition.key => {
      workload_description = trimspace(definition.workloadDescription)
      sub_workload_description = (
        definition.subWorkloadDescription == null ||
        trimspace(definition.subWorkloadDescription) == ""
      ) ? null : trimspace(definition.subWorkloadDescription)
    }
  }

  resource_group_name_map = {
    for key, definition in local.resource_group_definitions_by_key :
    key => substr(
      "rg-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}-${definition.workload_description}${definition.sub_workload_description == null ? "" : "-${definition.sub_workload_description}"}-${var.instance_number}",
      0,
      90
    )
  }

  app_service_subnet_plans = [
    for subnet in var.spoke_network_config.subnetPlan :
    subnet
    if subnet.key == "appService"
  ]
  private_endpoint_subnet_plans = [
    for subnet in var.spoke_network_config.subnetPlan :
    subnet
    if subnet.key == "privateEndpoints"
  ]
  postgresql_subnet_plans = [
    for subnet in var.spoke_network_config.subnetPlan :
    subnet
    if subnet.key == "postgresql"
  ]
  application_gateway_subnet_plans = [
    for subnet in var.spoke_network_config.subnetPlan :
    subnet
    if subnet.key == "applicationGateway"
  ]
  app_service_subnet_plan                      = try(local.app_service_subnet_plans[0], null)
  private_endpoint_subnet_plan                 = try(local.private_endpoint_subnet_plans[0], null)
  postgresql_subnet_plan                       = try(local.postgresql_subnet_plans[0], null)
  application_gateway_subnet_plan              = try(local.application_gateway_subnet_plans[0], null)
  spoke_network_workload_segment               = local.normalized_spoke_network_workload_description == null ? "" : "-${local.normalized_spoke_network_workload_description}"
  private_networking_enabled                   = var.deploy_private_networking && local.private_endpoint_subnet_plan != null && local.private_endpoint_subnet_plan.create
  web_app_private_networking_enabled           = local.private_networking_enabled && !var.deploy_ase_v3
  postgresql_enabled                           = var.deploy_postgresql
  postgresql_private_networking_enabled        = local.postgresql_enabled && var.deploy_private_networking && local.postgresql_subnet_plan != null && local.postgresql_subnet_plan.create
  postgresql_private_access_enabled            = local.postgresql_enabled && var.postgresql_config.privateAccessMode == "delegatedSubnet"
  use_existing_app_service_plan                = var.service_plan_config.existingPlanId != null
  deploy_app_service_plan                      = !local.use_existing_app_service_plan
  use_front_door_ingress                       = var.spoke_network_config.ingressOption == "frontDoor"
  use_application_gateway_ingress              = var.spoke_network_config.ingressOption == "applicationGateway"
  auto_approve_afd_private_endpoint            = local.use_front_door_ingress && local.web_app_private_networking_enabled && var.front_door_config.autoApprovePrivateEndpoint
  spoke_vnet_name                              = substr("vnet-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.spoke_network_workload_segment}-${var.instance_number}", 0, 80)
  spoke_vnet_resource_id                       = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${local.resource_group_name_map.network}/providers/Microsoft.Network/virtualNetworks/${local.spoke_vnet_name}"
  network_watcher_name                         = substr("nw-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.spoke_network_workload_segment}-${var.instance_number}", 0, 80)
  afd_pe_auto_approver_identity_name           = substr("id-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}-afdprivateendpointapprover-${var.instance_number}", 0, 128)
  afd_pe_auto_approver_script_name             = substr("script-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}-afdapproval-${var.instance_number}", 0, 90)
  afd_private_endpoint_approval_script_content = <<-SCRIPT
    rg_name="$ResourceGroupName"; webapp_ids=$(az webapp list -g $rg_name --query "[].id" -o tsv); for webapp_id in $webapp_ids; do fd_conn_ids=$(az network private-endpoint-connection list --id $webapp_id --query "[?properties.provisioningState == 'Pending'].id" -o tsv); for fd_conn_id in $fd_conn_ids; do az network private-endpoint-connection approve --id "$fd_conn_id" --description "ApprovedByCli"; done; done
  SCRIPT
  afd_private_endpoint_approval_force_update_tag = sha1(jsonencode({
    frontDoorProfileId = local.use_front_door_ingress ? module.front_door[0].resource_id : null
    webAppResourceId   = module.web_app.resource_id
    hostingRgName      = azurerm_resource_group.resourceGroups["hosting"].name
    originGroups       = var.front_door_config.originGroups
    afdEndpoints       = var.front_door_config.afdEndpoints
  }))
  resolved_log_analytics_workspace_id   = var.existing_log_analytics_id != null ? var.existing_log_analytics_id : module.log_analytics_workspace[0].resource_id
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
      name                     = local.spoke_vnet_name
      virtualNetworkResourceId = local.spoke_vnet_resource_id
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
