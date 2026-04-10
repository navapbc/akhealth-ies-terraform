locals {
  region_abbreviations = {
    global = "global"
  }

  region_abbreviation = local.region_abbreviations.global
  workload_segment    = trimspace(var.workload_description) == "" ? "" : "-${var.workload_description}"
  name                = substr(replace("fdfp-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", "-", ""), 0, 128)
  default_waf_method_block_rule = {
    name                       = "BlockMethod"
    action                     = "Block"
    enabledState               = "Enabled"
    priority                   = 10
    ruleType                   = "MatchRule"
    type                       = "MatchRule"
    rateLimitDurationInMinutes = 1
    rateLimitThreshold         = 100
    matchConditions = [{
      matchVariable   = "RequestMethod"
      operator        = "Equal"
      negateCondition = true
      matchValue      = ["GET", "OPTIONS", "HEAD"]
    }]
    conditions = null
  }
  custom_rules = concat(
    var.config.enableDefaultWafMethodBlock ? [local.default_waf_method_block_rule] : [],
    var.config.enableDefaultWafMethodBlock ? [] : var.config.wafCustomRules.rules
  )
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
    for_each = local.custom_rules

    content {
      name                           = custom_rule.value.name
      action                         = custom_rule.value.action
      enabled                        = coalesce(custom_rule.value.enabledState, "Enabled") == "Enabled"
      priority                       = custom_rule.value.priority
      type                           = coalesce(custom_rule.value.ruleType, custom_rule.value.type)
      rate_limit_duration_in_minutes = custom_rule.value.rateLimitDurationInMinutes
      rate_limit_threshold           = custom_rule.value.rateLimitThreshold

      dynamic "match_condition" {
        for_each = custom_rule.value.matchConditions != null ? custom_rule.value.matchConditions : (
          custom_rule.value.conditions != null ? custom_rule.value.conditions : []
        )
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
