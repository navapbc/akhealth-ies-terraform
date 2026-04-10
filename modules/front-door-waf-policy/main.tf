locals {
  region_abbreviations = {
    global = "global"
  }

  region_abbreviation = local.region_abbreviations.global
  workload_segment    = var.workload_description == null ? "" : "-${var.workload_description}"
  name                = substr(replace("fdfp-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", "-", ""), 0, 128)
  default_waf_method_block_rule = {
    name                       = "BlockMethod"
    action                     = "Block"
    enabledState               = "Enabled"
    priority                   = 10
    type                       = "MatchRule"
    rateLimitDurationInMinutes = 1
    rateLimitThreshold         = 100
    matchConditions = [{
      matchVariable   = "RequestMethod"
      operator        = "Equal"
      negateCondition = true
      matchValue      = ["GET", "OPTIONS", "HEAD"]
      selector        = null
      transforms      = null
    }]
  }
  custom_rules = concat(
    var.enable_default_waf_method_block ? [local.default_waf_method_block_rule] : [],
    var.waf_custom_rules
  )
}

resource "azurerm_cdn_frontdoor_firewall_policy" "this" {
  name                       = local.name
  resource_group_name        = var.resource_group_name
  sku_name                   = var.sku
  enabled                    = var.waf_policy_settings.enabledState == "Enabled"
  mode                       = var.waf_policy_settings.mode
  request_body_check_enabled = var.waf_policy_settings.requestBodyCheck == "Enabled"
  tags                       = var.tags

  dynamic "custom_rule" {
    for_each = local.custom_rules

    content {
      name                           = custom_rule.value.name
      action                         = custom_rule.value.action
      enabled                        = custom_rule.value.enabledState == null ? true : custom_rule.value.enabledState == "Enabled"
      priority                       = custom_rule.value.priority
      type                           = custom_rule.value.type
      rate_limit_duration_in_minutes = custom_rule.value.rateLimitDurationInMinutes
      rate_limit_threshold           = custom_rule.value.rateLimitThreshold

      dynamic "match_condition" {
        for_each = custom_rule.value.matchConditions
        content {
          match_variable     = match_condition.value.matchVariable
          operator           = match_condition.value.operator
          negation_condition = match_condition.value.negateCondition == null ? false : match_condition.value.negateCondition
          match_values       = match_condition.value.matchValue
          selector           = match_condition.value.selector
          transforms         = match_condition.value.transforms
        }
      }
    }
  }

  dynamic "managed_rule" {
    for_each = var.waf_managed_rule_sets
    content {
      type    = managed_rule.value.ruleSetType
      version = managed_rule.value.ruleSetVersion
      action  = managed_rule.value.ruleSetAction
    }
  }
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_cdn_frontdoor_firewall_policy.this.id
  name_suffix = local.name
  lock        = var.lock
}
