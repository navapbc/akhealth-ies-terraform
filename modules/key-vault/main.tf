data "azurerm_client_config" "current" {}

locals {
  workload_segment        = var.workload_description == null ? "" : "-${var.workload_description}"
  name                    = substr("kv-${var.system_abbreviation}-${var.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 24)
  create_private_endpoint = var.enable_default_private_endpoint
  private_endpoint_rg_name = coalesce(var.private_endpoint_resource_group_name, var.resource_group_name)
  private_dns_zone_rg_name = coalesce(var.private_dns_zone_resource_group_name, var.resource_group_name)
}

resource "azurerm_private_dns_zone" "default" {
  count = local.create_private_endpoint ? 1 : 0

  name                = var.default_private_dns_zone_name
  resource_group_name = local.private_dns_zone_rg_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "default" {
  for_each = local.create_private_endpoint ? {
    for link in var.default_private_dns_zone_virtual_network_links :
    link.name => link
  } : {}

  name                  = each.value.name
  resource_group_name   = local.private_dns_zone_rg_name
  private_dns_zone_name = azurerm_private_dns_zone.default[0].name
  virtual_network_id    = each.value.virtualNetworkResourceId
  registration_enabled  = coalesce(each.value.registrationEnabled, false)
  resolution_policy     = each.value.resolutionPolicy
}

resource "azurerm_key_vault" "this" {
  name                            = local.name
  location                        = var.location
  resource_group_name             = var.resource_group_name
  tenant_id                       = data.azurerm_client_config.current.tenant_id
  sku_name                        = lower(var.sku)
  enabled_for_deployment          = var.enable_vault_for_deployment
  enabled_for_template_deployment = var.enable_vault_for_template_deployment
  enabled_for_disk_encryption     = var.enable_vault_for_disk_encryption
  soft_delete_retention_days      = var.soft_delete_retention_in_days
  purge_protection_enabled        = var.enable_purge_protection
  public_network_access_enabled   = var.public_network_access == "Enabled"
  rbac_authorization_enabled      = true
  tags                            = var.tags

  dynamic "network_acls" {
    for_each = var.network_acls == null ? [] : [var.network_acls]
    content {
      bypass                     = network_acls.value.bypass
      default_action             = network_acls.value.defaultAction
      ip_rules                   = [for rule in network_acls.value.ipRules : rule.value]
      virtual_network_subnet_ids = [for rule in network_acls.value.virtualNetworkRules : rule.id]
    }
  }
}

resource "azurerm_key_vault_secret" "this" {
  for_each = {
    for secret in var.secrets :
    secret.name => secret
  }

  name            = each.value.name
  value           = each.value.value
  key_vault_id    = azurerm_key_vault.this.id
  content_type    = each.value.contentType
  not_before_date = each.value.attributes == null || each.value.attributes.nbf == null ? null : formatdate("YYYY-MM-DD'T'hh:mm:ssZ", timeadd("1970-01-01T00:00:00Z", "${each.value.attributes.nbf}s"))
  expiration_date = each.value.attributes == null || each.value.attributes.exp == null ? null : formatdate("YYYY-MM-DD'T'hh:mm:ssZ", timeadd("1970-01-01T00:00:00Z", "${each.value.attributes.exp}s"))
  tags            = each.value.tags == null ? var.tags : each.value.tags
}

resource "azurerm_key_vault_key" "this" {
  for_each = {
    for key in var.keys :
    key.name => key
  }

  name            = each.value.name
  key_vault_id    = azurerm_key_vault.this.id
  key_type        = each.value.kty == null ? "RSA" : each.value.kty
  key_size        = each.value.keySize
  curve           = each.value.curveName
  key_opts        = each.value.keyOps
  expiration_date = each.value.attributes == null || each.value.attributes.exp == null ? null : formatdate("YYYY-MM-DD'T'hh:mm:ssZ", timeadd("1970-01-01T00:00:00Z", "${each.value.attributes.exp}s"))
  not_before_date = each.value.attributes == null || each.value.attributes.nbf == null ? null : formatdate("YYYY-MM-DD'T'hh:mm:ssZ", timeadd("1970-01-01T00:00:00Z", "${each.value.attributes.nbf}s"))
  tags            = each.value.tags == null ? var.tags : each.value.tags
}

resource "azurerm_private_endpoint" "default" {
  count = local.create_private_endpoint ? 1 : 0

  name                = "pep-${var.system_abbreviation}-${var.region_abbreviation}-${var.environment_abbreviation}-keyvault-${var.instance_number}"
  location            = var.location
  resource_group_name = local.private_endpoint_rg_name
  subnet_id           = var.default_private_endpoint_subnet_resource_id
  tags                = var.tags

  private_service_connection {
    name                           = "plsc-${var.system_abbreviation}-${var.region_abbreviation}-${var.environment_abbreviation}-keyvault-${var.instance_number}"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = local.name
    private_dns_zone_ids = [azurerm_private_dns_zone.default[0].id]
  }
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_key_vault.this.id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  target_resource_id  = azurerm_key_vault.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_key_vault.this.id
  name_suffix = local.name
  lock        = var.lock
}
