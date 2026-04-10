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

variable "kind" {
  type = string
}

variable "service_plan_kind" {
  type = string
}

variable "server_farm_resource_id" {
  type = string
}

variable "https_only" {
  type = bool
}

variable "client_affinity_enabled" {
  type = bool
}

variable "public_network_access" {
  type    = string
  default = null
}

variable "site_config" {
  type = any
}

variable "outbound_vnet_routing" {
  type    = any
  default = null
}

variable "managed_identities" {
  type    = any
  default = null
}

variable "key_vault_access_identity_resource_id" {
  type    = string
  default = null
}

variable "virtual_network_subnet_resource_id" {
  type    = string
  default = null
}

variable "enabled" {
  type = bool
}

variable "disable_basic_publishing_credentials" {
  type    = bool
  default = false
}

variable "configs" {
  type    = list(any)
  default = []
}

variable "solution_application_insights_connection_string" {
  type    = string
  default = null
}

variable "function_host_storage_account" {
  type    = any
  default = null
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
  default = "privatelink.azurewebsites.net"
}

variable "default_private_dns_zone_virtual_network_links" {
  type    = list(any)
  default = []
}

variable "role_assignments" {
  type    = list(any)
  default = []
}

variable "diagnostic_settings" {
  type    = list(any)
  default = []
}

variable "lock" {
  type    = any
  default = null
}

variable "reserved" {
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
