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

variable "config" {
  type = object({
    afdPeAutoApproverIsolationScope = string
    managedIdentities = object({
      systemAssigned = bool
    })
    enableDefaultWafMethodBlock = bool
    wafCustomRules = object({
      rules = optional(list(object({
        name                       = string
        action                     = string
        enabledState               = optional(string)
        priority                   = number
        ruleType                   = optional(string)
        type                       = optional(string)
        rateLimitDurationInMinutes = optional(number)
        rateLimitThreshold         = optional(number)
        matchConditions = optional(list(object({
          matchVariable      = optional(string)
          match_variable     = optional(string)
          operator           = string
          negateCondition    = optional(bool)
          negation_condition = optional(bool)
          matchValue         = optional(list(string))
          match_values       = optional(list(string))
          selector           = optional(string)
          transforms         = optional(list(string))
        })), [])
        conditions = optional(list(object({
          match_variable     = string
          operator           = string
          negation_condition = optional(bool)
          match_values       = optional(list(string))
        })), [])
      })), [])
    })
    customDomains = list(any)
    ruleSets      = list(any)
    secrets       = list(any)
    roleAssignments = optional(list(object({
      key                                = optional(string)
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    originResponseTimeoutSeconds = number
    autoApprovePrivateEndpoint   = bool
    sku                          = string
    wafPolicySettings = object({
      enabledState     = string
      mode             = string
      requestBodyCheck = string
    })
    wafManagedRuleSets = list(object({
      ruleSetType        = string
      ruleSetVersion     = string
      ruleSetAction      = optional(string)
      ruleGroupOverrides = optional(list(any), [])
    }))
    originGroups            = list(any)
    afdEndpoints            = list(any)
    securityPatternsToMatch = optional(list(string), ["/*"])
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    diagnosticSettings = optional(list(object({
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
        enabled  = optional(bool)
      })), [])
    })), [])
  })
}

variable "tags" {
  type    = map(string)
  default = {}
}
