variable "name_prefix" {
  type = string
}

variable "target_resource_id" {
  type = string
}

variable "diagnostic_settings" {
  type = list(object({
    name                                = optional(string)
    workspaceResourceId                 = optional(string)
    logAnalyticsDestinationType         = optional(string)
    storageAccountResourceId            = optional(string)
    eventHubAuthorizationRuleResourceId = optional(string)
    eventHubName                        = optional(string)
    marketplacePartnerResourceId        = optional(string)
    logCategoriesAndGroups = optional(list(object({
      category      = optional(string)
      categoryGroup = optional(string)
    })), [])
    metricCategories = optional(list(object({
      category = string
      enabled  = optional(bool, true)
    })), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for diagnostic_setting in var.diagnostic_settings :
      length(compact([
        diagnostic_setting.workspaceResourceId,
        diagnostic_setting.storageAccountResourceId,
        diagnostic_setting.eventHubAuthorizationRuleResourceId,
        diagnostic_setting.marketplacePartnerResourceId,
      ])) > 0
    ])
    error_message = "Each diagnostic setting must declare at least one destination: workspaceResourceId, storageAccountResourceId, eventHubAuthorizationRuleResourceId, or marketplacePartnerResourceId."
  }

  validation {
    condition = alltrue([
      for diagnostic_setting in var.diagnostic_settings :
      length(diagnostic_setting.logCategoriesAndGroups) + length(diagnostic_setting.metricCategories) > 0
    ])
    error_message = "Each diagnostic setting must include at least one log category/group or metric category."
  }

  validation {
    condition = alltrue(flatten([
      for diagnostic_setting in var.diagnostic_settings : [
        for log_category in diagnostic_setting.logCategoriesAndGroups :
        length(compact([
          log_category.category,
          log_category.categoryGroup,
        ])) > 0
      ]
    ]))
    error_message = "Each logCategoriesAndGroups entry must set category or categoryGroup."
  }

  validation {
    condition = alltrue([
      for diagnostic_setting in var.diagnostic_settings :
      diagnostic_setting.eventHubName == null || trimspace(diagnostic_setting.eventHubName) == "" || (
        diagnostic_setting.eventHubAuthorizationRuleResourceId != null &&
        trimspace(diagnostic_setting.eventHubAuthorizationRuleResourceId) != ""
      )
    ])
    error_message = "eventHubName requires eventHubAuthorizationRuleResourceId."
  }

  validation {
    condition = alltrue([
      for diagnostic_setting in var.diagnostic_settings :
      diagnostic_setting.name == null || trimspace(diagnostic_setting.name) != ""
    ])
    error_message = "diagnostic setting names must be omitted or non-empty."
  }

  validation {
    condition = length(compact([
      for diagnostic_setting in var.diagnostic_settings :
      diagnostic_setting.name
      ])) == length(distinct(compact([
        for diagnostic_setting in var.diagnostic_settings :
        diagnostic_setting.name
    ])))
    error_message = "diagnostic setting names must be unique when provided."
  }
}
