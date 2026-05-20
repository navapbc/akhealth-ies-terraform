output "vnet_spoke_resource_id" {
  value = azurerm_virtual_network.this.id
}

output "vnet_spoke_name" {
  value = azurerm_virtual_network.this.name
}

output "snet_appsvc_resource_id" {
  value = azurerm_subnet.app_service.id
}

output "snet_appsvc_name" {
  value = azurerm_subnet.app_service.name
}

output "snet_pe_resource_id" {
  value = local.create_private_endpoint_subnet ? azurerm_subnet.private_endpoint[0].id : null
}

output "snet_pe_name" {
  value = local.create_private_endpoint_subnet ? azurerm_subnet.private_endpoint[0].name : null
}

output "snet_postgresql_resource_id" {
  value = local.create_postgresql_subnet ? azurerm_subnet.postgresql[0].id : null
}

output "snet_postgresql_name" {
  value = local.create_postgresql_subnet ? azurerm_subnet.postgresql[0].name : null
}

output "snet_appgw_resource_id" {
  value = local.create_app_gateway_subnet ? azurerm_subnet.app_gateway[0].id : null
}

output "snet_appgw_name" {
  value = local.create_app_gateway_subnet ? azurerm_subnet.app_gateway[0].name : null
}
