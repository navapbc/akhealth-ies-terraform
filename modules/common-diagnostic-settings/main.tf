locals {
  diagnostic_settings = {
    for index, diagnostic_setting in var.diagnostic_settings :
    coalesce(diagnostic_setting.name, tostring(index)) => diagnostic_setting
  }
}

resource "azurerm_monitor_diagnostic_setting" "this" {
  for_each = local.diagnostic_settings

  name                           = coalesce(each.value.name, "${var.name_prefix}-${each.key}")
  target_resource_id             = var.target_resource_id
  log_analytics_workspace_id     = each.value.workspaceResourceId
  log_analytics_destination_type = each.value.logAnalyticsDestinationType
  storage_account_id             = each.value.storageAccountResourceId
  eventhub_authorization_rule_id = each.value.eventHubAuthorizationRuleResourceId
  eventhub_name                  = each.value.eventHubName
  partner_solution_id            = each.value.marketplacePartnerResourceId

  dynamic "enabled_log" {
    for_each = each.value.logCategoriesAndGroups
    content {
      category       = enabled_log.value.category
      category_group = enabled_log.value.categoryGroup
    }
  }

  # Keep the provider's legacy metric block for now because the newer
  # enabled_metric block cannot express per-category enabled=false state.
  dynamic "metric" {
    for_each = each.value.metricCategories
    content {
      category = metric.value.category
      enabled  = metric.value.enabled
    }
  }
}
