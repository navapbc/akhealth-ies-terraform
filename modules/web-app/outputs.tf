output "name" {
  value = local.app_name
}

output "resource_id" {
  value = local.app_id
}

output "resource_group_name" {
  value = var.resource_group_name
}

output "location" {
  value = var.location
}

output "default_hostname" {
  value = local.default_hostname
}

output "system_assigned_mi_principal_id" {
  value = local.principal_id
}
