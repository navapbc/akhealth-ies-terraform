output "name" {
  value = azurerm_application_insights.this.name
}

output "resource_id" {
  value = azurerm_application_insights.this.id
}

output "resource_group_name" {
  value = azurerm_application_insights.this.resource_group_name
}

output "location" {
  value = azurerm_application_insights.this.location
}

output "application_id" {
  value = azurerm_application_insights.this.app_id
}

output "connection_string" {
  value = azurerm_application_insights.this.connection_string
}

output "instrumentation_key" {
  value     = azurerm_application_insights.this.instrumentation_key
  sensitive = true
}
