locals {
  diagnostic_settings = {
    for index, diagnostic_setting in var.diagnostic_settings :
    tostring(index) => diagnostic_setting
  }
}

resource "azurerm_monitor_diagnostic_setting" "this" {
  for_each = local.diagnostic_settings

  name                           = coalesce(try(each.value.name, null), "${var.name_prefix}-${each.key}")
  target_resource_id             = var.target_resource_id
  log_analytics_workspace_id     = try(each.value.workspaceResourceId, null)
  log_analytics_destination_type = try(each.value.logAnalyticsDestinationType, null)
  storage_account_id             = try(each.value.storageAccountResourceId, null)
  eventhub_authorization_rule_id = try(each.value.eventHubAuthorizationRuleResourceId, null)
  eventhub_name                  = try(each.value.eventHubName, null)
  partner_solution_id            = try(each.value.marketplacePartnerResourceId, null)

  dynamic "enabled_log" {
    for_each = try(each.value.logCategoriesAndGroups, [])
    content {
      category       = try(enabled_log.value.category, null)
      category_group = try(enabled_log.value.categoryGroup, null)
    }
  }

  dynamic "metric" {
    for_each = try(each.value.metricCategories, [])
    content {
      category = metric.value.category
      enabled  = try(metric.value.enabled, true)
    }
  }
}
