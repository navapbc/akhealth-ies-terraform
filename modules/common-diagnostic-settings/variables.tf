variable "name_prefix" {
  type = string
}

variable "target_resource_id" {
  type = string
}

variable "diagnostic_settings" {
  type    = list(any)
  default = []
}
