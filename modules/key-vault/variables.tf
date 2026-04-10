variable "resource_group_name" {
  type = string
}

variable "system_abbreviation" {
  type = string
}

variable "environment_abbreviation" {
  type = string
}

variable "instance_number" {
  type = string
}

variable "workload_description" {
  type    = string
  default = ""
}

variable "location" {
  type = string
}

variable "secrets" {
  type    = list(any)
  default = []
}

variable "keys" {
  type    = list(any)
  default = []
}

variable "enable_vault_for_deployment" {
  type = bool
}

variable "enable_vault_for_template_deployment" {
  type = bool
}

variable "enable_vault_for_disk_encryption" {
  type = bool
}

variable "soft_delete_retention_in_days" {
  type = number
}

variable "create_mode" {
  type    = string
  default = "default"
}

variable "enable_purge_protection" {
  type = bool
}

variable "sku" {
  type = string
}

variable "network_acls" {
  type    = any
  default = null
}

variable "public_network_access" {
  type = string
}

variable "lock" {
  type    = any
  default = null
}

variable "role_assignments" {
  type    = list(any)
  default = []
}

variable "enable_default_private_endpoint" {
  type    = bool
  default = false
}

variable "default_private_endpoint_subnet_resource_id" {
  type    = string
  default = null
}

variable "default_private_dns_zone_name" {
  type    = string
  default = "privatelink.vaultcore.azure.net"
}

variable "default_private_dns_zone_virtual_network_links" {
  type    = list(any)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "diagnostic_settings" {
  type    = list(any)
  default = []
}
