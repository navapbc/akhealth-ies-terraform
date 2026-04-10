locals {
  region_abbreviations = {
    global = "global"
  }

  region_abbreviation = local.region_abbreviations.global
  workload_segment    = trimspace(var.workload_description) == "" ? "" : "-${var.workload_description}"
  name                = substr(replace("fdfp-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", "-", ""), 0, 128)
}

resource "azurerm_cdn_frontdoor_firewall_policy" "this" {
  name                       = local.name
  resource_group_name        = var.resource_group_name
  sku_name                   = var.config.sku
  enabled                    = try(var.config.wafPolicySettings.enabledState, "Enabled") == "Enabled"
  mode                       = try(var.config.wafPolicySettings.mode, "Prevention")
  request_body_check_enabled = try(var.config.wafPolicySettings.requestBodyCheck, "Enabled") == "Enabled"
  tags                       = var.tags

  dynamic "custom_rule" {
    for_each = try(var.config.enableDefaultWafMethodBlock, false) ? [{
      name                       = "BlockMethod"
      action                     = "Block"
      enabled                    = true
      priority                   = 10
      type                       = "MatchRule"
      rateLimitDurationInMinutes = 1
      rateLimitThreshold         = 100
      conditions = [{
        match_variable     = "RequestMethod"
        operator           = "Equal"
        negation_condition = true
        match_values       = ["GET", "OPTIONS", "HEAD"]
      }]
    }] : try(var.config.wafCustomRules.rules, [])

    content {
      name                           = custom_rule.value.name
      action                         = custom_rule.value.action
      enabled                        = try(custom_rule.value.enabledState, "Enabled") == "Enabled"
      priority                       = custom_rule.value.priority
      type                           = try(custom_rule.value.ruleType, custom_rule.value.type)
      rate_limit_duration_in_minutes = try(custom_rule.value.rateLimitDurationInMinutes, null)
      rate_limit_threshold           = try(custom_rule.value.rateLimitThreshold, null)

      dynamic "match_condition" {
        for_each = try(custom_rule.value.matchConditions, custom_rule.value.conditions, [])
        content {
          match_variable     = try(match_condition.value.matchVariable, match_condition.value.match_variable)
          operator           = match_condition.value.operator
          negation_condition = try(match_condition.value.negateCondition, try(match_condition.value.negation_condition, false))
          match_values       = try(match_condition.value.matchValue, try(match_condition.value.match_values, []))
          selector           = try(match_condition.value.selector, null)
          transforms         = try(match_condition.value.transforms, null)
        }
      }
    }
  }

  dynamic "managed_rule" {
    for_each = try(var.config.wafManagedRuleSets, [])
    content {
      type    = managed_rule.value.ruleSetType
      version = managed_rule.value.ruleSetVersion
      action  = try(managed_rule.value.ruleSetAction, null)
    }
  }
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_cdn_frontdoor_firewall_policy.this.id
  name_suffix = local.name
  lock        = try(var.config.lock, null)
}
