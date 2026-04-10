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

variable "subnet_resource_id" {
  type = string
}

variable "cluster_settings" {
  type    = list(any)
  default = []
}

variable "dedicated_host_count" {
  type    = number
  default = null
}

variable "internal_load_balancing_mode" {
  type    = string
  default = null
}

variable "zone_redundant" {
  type    = bool
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

variable "lock" {
  type    = any
  default = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
