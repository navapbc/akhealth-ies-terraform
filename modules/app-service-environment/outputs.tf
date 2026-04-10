output "name" {
  value = azurerm_app_service_environment_v3.this.name
}

output "resource_id" {
  value = azurerm_app_service_environment_v3.this.id
}

output "internal_inbound_ip_address" {
  value = try(azurerm_app_service_environment_v3.this.internal_inbound_ip_addresses[0], null)
}
