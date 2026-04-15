output "spoke_resource_group_name" {
  value = azurerm_resource_group.solution["network"].name
}

output "resource_group_name_map" {
  value = local.resource_group_name_map
}

output "network_resource_group_name" {
  value = azurerm_resource_group.solution["network"].name
}

output "network_edge_resource_group_name" {
  value = azurerm_resource_group.solution["networkEdge"].name
}

output "hosting_resource_group_name" {
  value = azurerm_resource_group.solution["hosting"].name
}

output "data_resource_group_name" {
  value = azurerm_resource_group.solution["data"].name
}

output "operations_resource_group_name" {
  value = azurerm_resource_group.solution["operations"].name
}

output "spoke_vnet_resource_id" {
  value = module.network.vnet_spoke_resource_id
}

output "spoke_vnet_name" {
  value = module.network.vnet_spoke_name
}

output "key_vault_resource_id" {
  value = module.key_vault.resource_id
}

output "key_vault_name" {
  value = module.key_vault.name
}

output "web_app_name" {
  value = module.web_app.name
}

output "web_app_host_name" {
  value = module.web_app.default_hostname
}

output "web_app_resource_id" {
  value = module.web_app.resource_id
}

output "web_app_location" {
  value = module.web_app.location
}

output "web_app_managed_identity_principal_id" {
  value = module.web_app.system_assigned_mi_principal_id
}

output "app_service_plan_resource_id" {
  value = local.resolved_app_service_plan_resource_id
}

output "internal_inbound_ip_address" {
  value = var.deploy_ase_v3 ? module.app_service_environment[0].internal_inbound_ip_address : null
}

output "ase_name" {
  value = var.deploy_ase_v3 ? module.app_service_environment[0].name : null
}

output "log_analytics_workspace_used_resource_id" {
  value = local.resolved_log_analytics_workspace_id
}

output "log_analytics_workspace_created_name" {
  value = trimspace(var.existing_log_analytics_id == null ? "" : var.existing_log_analytics_id) == "" ? module.log_analytics_workspace[0].name : null
}

output "postgresql_admin_group_object_id" {
  value = var.deploy_postgresql ? var.postgresql_admin_group_config.objectId : null
}

output "postgresql_admin_group_name" {
  value = var.deploy_postgresql ? var.postgresql_admin_group_config.displayName : null
}

output "postgresql_server_name" {
  value = var.deploy_postgresql ? module.postgresql[0].name : null
}

output "postgresql_server_resource_id" {
  value = var.deploy_postgresql ? module.postgresql[0].resource_id : null
}

output "postgresql_server_fqdn" {
  value = var.deploy_postgresql ? module.postgresql[0].fqdn : null
}

output "postgresql_private_dns_zone_name" {
  value = local.postgresql_private_access_enabled ? module.postgresql[0].private_dns_zone_name : null
}
