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

variable "sku" {
  type = string
}

variable "capacity" {
  type = number
}

variable "autoscale_min_capacity" {
  type    = number
  default = null
}

variable "autoscale_max_capacity" {
  type    = number
  default = null
}

variable "enable_http2" {
  type    = bool
  default = false
}

variable "enable_fips" {
  type    = bool
  default = false
}

variable "availability_zones" {
  type    = list(number)
  default = []
}

variable "firewall_policy_resource_id" {
  type    = string
  default = null
}

variable "gateway_ip_configurations" {
  type    = list(any)
  default = []
}

variable "frontend_ip_configurations" {
  type    = list(any)
  default = []
}

variable "frontend_ports" {
  type    = list(any)
  default = []
}

variable "backend_address_pools" {
  type    = list(any)
  default = []
}

variable "backend_http_settings_collection" {
  type    = list(any)
  default = []
}

variable "probes" {
  type    = list(any)
  default = []
}

variable "http_listeners" {
  type    = list(any)
  default = []
}

variable "request_routing_rules" {
  type    = list(any)
  default = []
}

variable "managed_identities" {
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

variable "lock" {
  type    = any
  default = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
