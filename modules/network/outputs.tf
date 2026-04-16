output "vnet_spoke_resource_id" {
  value = azurerm_virtual_network.this.id
}

output "vnet_spoke_name" {
  value = azurerm_virtual_network.this.name
}

output "snet_appsvc_resource_id" {
  value = azurerm_subnet.this["appService"].id
}

output "snet_appsvc_name" {
  value = azurerm_subnet.this["appService"].name
}

output "snet_pe_resource_id" {
  value = try(azurerm_subnet.this["privateEndpoints"].id, null)
}

output "snet_pe_name" {
  value = try(azurerm_subnet.this["privateEndpoints"].name, null)
}

output "snet_postgresql_resource_id" {
  value = try(azurerm_subnet.this["postgresql"].id, null)
}

output "snet_postgresql_name" {
  value = try(azurerm_subnet.this["postgresql"].name, null)
}

output "snet_appgw_resource_id" {
  value = try(azurerm_subnet.this["applicationGateway"].id, null)
}

output "snet_appgw_name" {
  value = try(azurerm_subnet.this["applicationGateway"].name, null)
}
