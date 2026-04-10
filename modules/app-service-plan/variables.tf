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

variable "sku_name" {
  type = string
}

variable "sku_capacity" {
  type = number
}

variable "service_plan_kind" {
  type = string
}

variable "workload_kind" {
  type = string
}

variable "app_service_environment_resource_id" {
  type    = string
  default = null
}

variable "per_site_scaling" {
  type = bool
}

variable "maximum_elastic_worker_count" {
  type = number
}

variable "zone_redundant" {
  type = bool
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
