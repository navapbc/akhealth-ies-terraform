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
  value = length(azurerm_subnet.private_endpoint) == 0 ? null : azurerm_subnet.private_endpoint[0].id
}

output "snet_pe_name" {
  value = length(azurerm_subnet.private_endpoint) == 0 ? null : azurerm_subnet.private_endpoint[0].name
}

output "snet_postgresql_resource_id" {
  value = length(azurerm_subnet.postgresql) == 0 ? null : azurerm_subnet.postgresql[0].id
}

output "snet_postgresql_name" {
  value = length(azurerm_subnet.postgresql) == 0 ? null : azurerm_subnet.postgresql[0].name
}

output "snet_appgw_resource_id" {
  value = length(azurerm_subnet.app_gateway) == 0 ? null : azurerm_subnet.app_gateway[0].id
}

output "snet_appgw_name" {
  value = length(azurerm_subnet.app_gateway) == 0 ? null : azurerm_subnet.app_gateway[0].name
}
