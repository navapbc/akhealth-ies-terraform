output "name" {
  value = azurerm_cdn_frontdoor_profile.this.name
}

output "resource_id" {
  value = azurerm_cdn_frontdoor_profile.this.id
}

output "front_door_endpoint_host_names" {
  value = values(azurerm_cdn_frontdoor_endpoint.this)[*].host_name
}

output "afd_endpoint_resource_ids" {
  value = values(azurerm_cdn_frontdoor_endpoint.this)[*].id
}

output "custom_domain_resource_ids" {
  value = []
}
