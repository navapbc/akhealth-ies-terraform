output "resource_id" {
  value = azurerm_key_vault.this.id
}

output "resource_group_name" {
  value = azurerm_key_vault.this.resource_group_name
}

output "name" {
  value = azurerm_key_vault.this.name
}

output "uri" {
  value = azurerm_key_vault.this.vault_uri
}

output "location" {
  value = azurerm_key_vault.this.location
}
