locals {
  region_abbreviations = {
    eastus         = "eus"
    eastus2        = "eus2"
    westus         = "wus"
    westus2        = "wus2"
    westus3        = "wus3"
    centralus      = "cus"
    northcentralus = "ncus"
    southcentralus = "scus"
    westcentralus  = "wcus"
    global         = "global"
  }

  region_abbreviation           = local.region_abbreviations[var.location]
  workload_segment              = var.workload_description == null ? "" : "-${var.workload_description}"
  name                          = substr("app-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 60)
  kind_lower                    = lower(var.kind)
  is_function_app               = strcontains(local.kind_lower, "functionapp")
  is_linux                      = strcontains(local.kind_lower, "linux") || var.reserved || lower(var.service_plan_kind) == "linux"
  create_private_endpoint       = var.enable_default_private_endpoint
  identity_enabled              = var.managed_identities != null && var.managed_identities.systemAssigned
  public_network_access_enabled = var.public_network_access == null ? null : var.public_network_access == "Enabled"
  merged_app_settings = merge(
    var.app_settings,
    var.use_solution_application_insights ? {
      APPLICATIONINSIGHTS_CONNECTION_STRING = var.solution_application_insights_connection_string
    } : {}
  )
}

resource "azurerm_private_dns_zone" "default" {
  count = local.create_private_endpoint ? 1 : 0

  name                = var.default_private_dns_zone_name
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "default" {
  for_each = local.create_private_endpoint ? {
    for link in var.default_private_dns_zone_virtual_network_links :
    link.name => link
  } : {}

  name                  = each.value.name
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.default[0].name
  virtual_network_id    = each.value.virtualNetworkResourceId
  registration_enabled  = each.value.registrationEnabled == null ? false : each.value.registrationEnabled
}

resource "azurerm_windows_web_app" "this" {
  count = !local.is_function_app && !local.is_linux ? 1 : 0

  name                                           = local.name
  location                                       = var.location
  resource_group_name                            = var.resource_group_name
  service_plan_id                                = var.server_farm_resource_id
  enabled                                        = var.enabled
  https_only                                     = var.https_only
  client_affinity_enabled                        = var.client_affinity_enabled
  public_network_access_enabled                  = local.public_network_access_enabled
  virtual_network_subnet_id                      = var.virtual_network_subnet_resource_id
  key_vault_reference_identity_id                = var.key_vault_access_identity_resource_id
  tags                                           = var.tags
  app_settings                                   = local.merged_app_settings
  ftp_publish_basic_authentication_enabled       = !var.disable_basic_publishing_credentials
  webdeploy_publish_basic_authentication_enabled = !var.disable_basic_publishing_credentials

  dynamic "identity" {
    for_each = local.identity_enabled ? [1] : []
    content {
      type = "SystemAssigned"
    }
  }

  site_config {
    always_on                         = var.site_config.alwaysOn
    ftps_state                        = var.site_config.ftpsState
    health_check_path                 = var.site_config.healthCheckPath
    health_check_eviction_time_in_min = var.site_config.healthCheckPath == null ? null : 2
    http2_enabled                     = var.site_config.http20Enabled
    local_mysql_enabled               = var.site_config.localMySqlEnabled == null ? false : var.site_config.localMySqlEnabled
    minimum_tls_version               = var.site_config.minTlsVersion
    use_32_bit_worker                 = false
    vnet_route_all_enabled            = var.outbound_vnet_routing == null ? null : var.outbound_vnet_routing.allTraffic
    websockets_enabled                = true
  }
}

resource "azurerm_linux_web_app" "this" {
  count = !local.is_function_app && local.is_linux ? 1 : 0

  name                                     = local.name
  location                                 = var.location
  resource_group_name                      = var.resource_group_name
  service_plan_id                          = var.server_farm_resource_id
  enabled                                  = var.enabled
  https_only                               = var.https_only
  client_affinity_enabled                  = var.client_affinity_enabled
  public_network_access_enabled            = local.public_network_access_enabled
  virtual_network_subnet_id                = var.virtual_network_subnet_resource_id
  key_vault_reference_identity_id          = var.key_vault_access_identity_resource_id
  tags                                     = var.tags
  app_settings                             = local.merged_app_settings
  ftp_publish_basic_authentication_enabled = !var.disable_basic_publishing_credentials

  dynamic "identity" {
    for_each = local.identity_enabled ? [1] : []
    content {
      type = "SystemAssigned"
    }
  }

  site_config {
    always_on                         = var.site_config.alwaysOn
    ftps_state                        = var.site_config.ftpsState
    health_check_path                 = var.site_config.healthCheckPath
    health_check_eviction_time_in_min = var.site_config.healthCheckPath == null ? null : 2
    http2_enabled                     = var.site_config.http20Enabled
    local_mysql_enabled               = var.site_config.localMySqlEnabled == null ? false : var.site_config.localMySqlEnabled
    minimum_tls_version               = var.site_config.minTlsVersion
  }
}

resource "azurerm_windows_function_app" "this" {
  count = local.is_function_app && !local.is_linux ? 1 : 0

  name                                           = local.name
  location                                       = var.location
  resource_group_name                            = var.resource_group_name
  service_plan_id                                = var.server_farm_resource_id
  enabled                                        = var.enabled
  https_only                                     = var.https_only
  public_network_access_enabled                  = local.public_network_access_enabled
  virtual_network_subnet_id                      = var.virtual_network_subnet_resource_id
  storage_account_name                           = var.function_host_storage_account == null ? null : var.function_host_storage_account.name
  storage_uses_managed_identity                  = true
  tags                                           = var.tags
  app_settings                                   = local.merged_app_settings
  ftp_publish_basic_authentication_enabled       = !var.disable_basic_publishing_credentials
  webdeploy_publish_basic_authentication_enabled = !var.disable_basic_publishing_credentials

  dynamic "identity" {
    for_each = local.identity_enabled ? [1] : []
    content {
      type = "SystemAssigned"
    }
  }

  site_config {
    always_on                         = var.site_config.alwaysOn
    ftps_state                        = var.site_config.ftpsState
    health_check_path                 = var.site_config.healthCheckPath
    health_check_eviction_time_in_min = var.site_config.healthCheckPath == null ? null : 2
    http2_enabled                     = var.site_config.http20Enabled
    minimum_tls_version               = var.site_config.minTlsVersion
  }
}

resource "azurerm_linux_function_app" "this" {
  count = local.is_function_app && local.is_linux ? 1 : 0

  name                                     = local.name
  location                                 = var.location
  resource_group_name                      = var.resource_group_name
  service_plan_id                          = var.server_farm_resource_id
  enabled                                  = var.enabled
  https_only                               = var.https_only
  public_network_access_enabled            = local.public_network_access_enabled
  virtual_network_subnet_id                = var.virtual_network_subnet_resource_id
  storage_account_name                     = var.function_host_storage_account == null ? null : var.function_host_storage_account.name
  storage_uses_managed_identity            = true
  tags                                     = var.tags
  app_settings                             = local.merged_app_settings
  ftp_publish_basic_authentication_enabled = !var.disable_basic_publishing_credentials

  dynamic "identity" {
    for_each = local.identity_enabled ? [1] : []
    content {
      type = "SystemAssigned"
    }
  }

  site_config {
    always_on                         = var.site_config.alwaysOn
    ftps_state                        = var.site_config.ftpsState
    health_check_path                 = var.site_config.healthCheckPath
    health_check_eviction_time_in_min = var.site_config.healthCheckPath == null ? null : 2
    http2_enabled                     = var.site_config.http20Enabled
    minimum_tls_version               = var.site_config.minTlsVersion
  }
}

locals {
  app_id = local.is_function_app ? (
    local.is_linux ? azurerm_linux_function_app.this[0].id : azurerm_windows_function_app.this[0].id
  ) : (
    local.is_linux ? azurerm_linux_web_app.this[0].id : azurerm_windows_web_app.this[0].id
  )
  app_name = local.is_function_app ? (
    local.is_linux ? azurerm_linux_function_app.this[0].name : azurerm_windows_function_app.this[0].name
  ) : (
    local.is_linux ? azurerm_linux_web_app.this[0].name : azurerm_windows_web_app.this[0].name
  )
  default_hostname = local.is_function_app ? (
    local.is_linux ? azurerm_linux_function_app.this[0].default_hostname : azurerm_windows_function_app.this[0].default_hostname
  ) : (
    local.is_linux ? azurerm_linux_web_app.this[0].default_hostname : azurerm_windows_web_app.this[0].default_hostname
  )
  principal_id = !local.identity_enabled ? null : (
    local.is_function_app ? (
      local.is_linux ? azurerm_linux_function_app.this[0].identity[0].principal_id : azurerm_windows_function_app.this[0].identity[0].principal_id
    ) : (
      local.is_linux ? azurerm_linux_web_app.this[0].identity[0].principal_id : azurerm_windows_web_app.this[0].identity[0].principal_id
    )
  )
  app_resource_group_name = local.is_function_app ? (
    local.is_linux ? azurerm_linux_function_app.this[0].resource_group_name : azurerm_windows_function_app.this[0].resource_group_name
  ) : (
    local.is_linux ? azurerm_linux_web_app.this[0].resource_group_name : azurerm_windows_web_app.this[0].resource_group_name
  )
  app_location = local.is_function_app ? (
    local.is_linux ? azurerm_linux_function_app.this[0].location : azurerm_windows_function_app.this[0].location
  ) : (
    local.is_linux ? azurerm_linux_web_app.this[0].location : azurerm_windows_web_app.this[0].location
  )
}

resource "azurerm_private_endpoint" "default" {
  count = local.create_private_endpoint ? 1 : 0

  name                = "pep-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}-appservice-${var.instance_number}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.default_private_endpoint_subnet_resource_id
  tags                = var.tags

  private_service_connection {
    name                           = "plsc-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}-appservice-${var.instance_number}"
    private_connection_resource_id = local.app_id
    subresource_names              = ["sites"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [azurerm_private_dns_zone.default[0].id]
  }
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = local.app_id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  name_prefix         = local.name
  target_resource_id  = local.app_id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = local.app_id
  name_suffix = local.name
  lock        = var.lock
}
