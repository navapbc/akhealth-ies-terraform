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

variable "workspace_resource_id" {
  type = string
}

variable "application_type" {
  type = string
}

variable "disable_ip_masking" {
  type = bool
}

variable "disable_local_auth" {
  type = bool
}

variable "force_customer_storage_for_profiler" {
  type = bool
}

variable "public_network_access_for_ingestion" {
  type = string
}

variable "public_network_access_for_query" {
  type = string
}

variable "retention_in_days" {
  type = number
}

variable "sampling_percentage" {
  type = number
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

variable "tags" {
  type    = map(string)
  default = {}
}
