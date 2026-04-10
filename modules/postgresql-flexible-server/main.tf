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

  region_abbreviation    = lookup(local.region_abbreviations, var.location, replace(var.location, " ", ""))
  name                   = substr("psqlfx-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}-${var.workload_description}-${var.instance_number}", 0, 63)
  private_access_enabled = var.private_access_mode == "delegatedSubnet"
  private_dns_zone_label = substr("pdz-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}-${var.workload_description}-${var.instance_number}", 0, 63)
  private_dns_zone_name  = "${local.private_dns_zone_label}.postgres.database.azure.com"
  storage_mb             = var.storage_size_gb * 1024
  public_network_access  = var.public_network_access == "Enabled"
  sku_name = startswith(var.sku_name, "B_") || startswith(var.sku_name, "GP_") || startswith(var.sku_name, "MO_") ? var.sku_name : (
    var.tier == "Burstable" ? "B_${var.sku_name}" : (
      var.tier == "GeneralPurpose" ? "GP_${var.sku_name}" : "MO_${var.sku_name}"
    )
  )
}

resource "azurerm_private_dns_zone" "this" {
  count = local.private_access_enabled ? 1 : 0

  name                = local.private_dns_zone_name
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each = local.private_access_enabled ? {
    for link in var.private_dns_zone_virtual_network_links :
    link.name => link
  } : {}

  name                  = each.value.name
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.this[0].name
  virtual_network_id    = each.value.virtualNetworkResourceId
  registration_enabled  = try(each.value.registrationEnabled, false)
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                          = local.name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  version                       = var.engine_version
  sku_name                      = local.sku_name
  storage_mb                    = local.storage_mb
  backup_retention_days         = var.backup_retention_days
  auto_grow_enabled             = var.auto_grow == "Enabled"
  geo_redundant_backup_enabled  = var.geo_redundant_backup == "Enabled"
  public_network_access_enabled = local.public_network_access
  delegated_subnet_id           = local.private_access_enabled ? var.delegated_subnet_resource_id : null
  private_dns_zone_id           = local.private_access_enabled ? azurerm_private_dns_zone.this[0].id : null
  zone                          = var.availability_zone == -1 ? null : tostring(var.availability_zone)
  tags                          = var.tags

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = var.administrator_group_tenant_id
  }

  dynamic "high_availability" {
    for_each = var.high_availability == "Disabled" ? [] : [1]
    content {
      mode                      = var.high_availability
      standby_availability_zone = var.high_availability == "SameZone" ? tostring(var.availability_zone) : tostring(var.high_availability_zone)
    }
  }
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "this" {
  server_name         = azurerm_postgresql_flexible_server.this.name
  resource_group_name = var.resource_group_name
  tenant_id           = var.administrator_group_tenant_id
  object_id           = var.administrator_group_object_id
  principal_name      = var.administrator_group_display_name
  principal_type      = "Group"
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  for_each = {
    for database in var.databases :
    database.name => database
  }

  name      = each.value.name
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = try(each.value.charset, null)
  collation = try(each.value.collation, null)
}

resource "azurerm_postgresql_flexible_server_configuration" "this" {
  for_each = {
    for configuration in var.configurations :
    configuration.name => configuration
  }

  name      = each.value.name
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = try(each.value.value, null)
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_postgresql_flexible_server.this.id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  name_prefix         = local.name
  target_resource_id  = azurerm_postgresql_flexible_server.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_postgresql_flexible_server.this.id
  name_suffix = local.name
  lock        = var.lock
}
