output "name" {
  value = azurerm_service_plan.this.name
}

output "resource_id" {
  value = azurerm_service_plan.this.id
}

output "location" {
  value = azurerm_service_plan.this.location
}

output "resource_group_name" {
  value = azurerm_service_plan.this.resource_group_name
}
