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
  default = null
  validation {
    condition     = var.workload_description == null || trimspace(var.workload_description) != ""
    error_message = "workload_description must be null or a non-empty string."
  }
}

variable "location" {
  type = string

  validation {
    condition = contains([
      "eastus",
      "eastus2",
      "westus",
      "westus2",
      "westus3",
      "centralus",
      "northcentralus",
      "southcentralus",
      "westcentralus",
      "global",
    ], var.location)
    error_message = "location must be one of the supported naming locations for this module."
  }
}

variable "profile_resource_id" {
  type = string
}

variable "waf_policy_resource_id" {
  type = string
}

variable "domain_resource_ids" {
  type = list(string)

  validation {
    condition = (
      length(var.domain_resource_ids) > 0 &&
      alltrue([for id in var.domain_resource_ids : trimspace(id) != ""])
    )
    error_message = "domain_resource_ids must contain at least one non-empty resource ID."
  }
}

variable "security_patterns_to_match" {
  type = list(string)

  validation {
    condition = (
      length(var.security_patterns_to_match) > 0 &&
      alltrue([for pattern in var.security_patterns_to_match : trimspace(pattern) != ""])
    )
    error_message = "security_patterns_to_match must contain at least one non-empty pattern."
  }
}
