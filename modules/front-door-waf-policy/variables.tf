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
  default = null

  validation {
    condition     = var.workload_description == null || trimspace(var.workload_description) != ""
    error_message = "workload_description must be null or a non-empty string."
  }
}

variable "sku" {
  type = string
}

variable "enable_default_waf_method_block" {
  type = bool
}

variable "waf_custom_rules" {
  type = list(object({
    name                       = string
    action                     = string
    enabledState               = optional(string)
    priority                   = number
    type                       = string
    rateLimitDurationInMinutes = optional(number)
    rateLimitThreshold         = optional(number)
    matchConditions = optional(list(object({
      matchVariable   = string
      operator        = string
      negateCondition = optional(bool)
      matchValue      = optional(list(string), [])
      selector        = optional(string)
      transforms      = optional(list(string))
    })), [])
  }))
  default = []
}

variable "waf_policy_settings" {
  type = object({
    enabledState     = string
    mode             = string
    requestBodyCheck = string
  })

  validation {
    condition     = contains(["Enabled", "Disabled"], var.waf_policy_settings.enabledState)
    error_message = "waf_policy_settings.enabledState must be Enabled or Disabled."
  }

  validation {
    condition     = contains(["Detection", "Prevention"], var.waf_policy_settings.mode)
    error_message = "waf_policy_settings.mode must be Detection or Prevention."
  }

  validation {
    condition     = contains(["Enabled", "Disabled"], var.waf_policy_settings.requestBodyCheck)
    error_message = "waf_policy_settings.requestBodyCheck must be Enabled or Disabled."
  }
}

variable "waf_managed_rule_sets" {
  type = list(object({
    ruleSetType    = string
    ruleSetVersion = string
    ruleSetAction  = optional(string)
  }))
  default = []
}

variable "lock" {
  type = object({
    kind  = string
    name  = optional(string)
    notes = optional(string)
  })
  default = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
