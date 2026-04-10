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

variable "profile_resource_id" {
  type = string
}

variable "waf_policy_resource_id" {
  type = string
}

variable "domain_resource_ids" {
  type = list(string)
}

variable "security_patterns_to_match" {
  type = list(string)
}
