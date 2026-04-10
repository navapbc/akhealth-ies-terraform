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

variable "config" {
  type = any
}

variable "workload_origin_host_name" {
  type = string
}

variable "workload_origin_resource_id" {
  type = string
}

variable "workload_origin_location" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
