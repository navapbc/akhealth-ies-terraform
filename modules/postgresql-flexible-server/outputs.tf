output "name" {
  value = azurerm_postgresql_flexible_server.this.name
}

output "resource_id" {
  value = azurerm_postgresql_flexible_server.this.id
}

output "resource_group_name" {
  value = var.resource_group_name
}

output "location" {
  value = azurerm_postgresql_flexible_server.this.location
}

output "fqdn" {
  value = azurerm_postgresql_flexible_server.this.fqdn
}

output "private_dns_zone_name" {
  value = local.private_access_enabled ? azurerm_private_dns_zone.this[0].name : null
}
