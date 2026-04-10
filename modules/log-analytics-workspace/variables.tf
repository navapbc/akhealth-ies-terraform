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

variable "tags" {
  type    = map(string)
  default = {}
}

variable "sku" {
  type = string
}

variable "retention_in_days" {
  type = number
}

variable "enable_log_access_using_only_resource_permissions" {
  type = bool
}

variable "disable_local_auth" {
  type = bool
}

variable "public_network_access_for_ingestion" {
  type = string
}

variable "public_network_access_for_query" {
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

variable "diagnostic_settings" {
  type    = list(any)
  default = []
}
