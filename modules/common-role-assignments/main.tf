data "azurerm_client_config" "current" {}

locals {
  assignments = {
    for index, assignment in var.role_assignments :
    tostring(index) => assignment
  }
}

resource "azurerm_role_assignment" "this" {
  for_each = local.assignments

  scope                                  = var.scope
  principal_id                           = each.value.principalId
  principal_type                         = try(each.value.principalType, null)
  description                            = try(each.value.description, null)
  condition                              = try(each.value.condition, null)
  condition_version                      = try(each.value.conditionVersion, null)
  delegated_managed_identity_resource_id = try(each.value.delegatedManagedIdentityResourceId, null)
  name                                   = try(each.value.name, null)

  role_definition_id = length(regexall("^/subscriptions/.+/providers/Microsoft.Authorization/roleDefinitions/.+$", each.value.roleDefinitionIdOrName)) > 0 ? each.value.roleDefinitionIdOrName : (
    length(regexall("^[0-9a-fA-F-]{36}$", each.value.roleDefinitionIdOrName)) > 0 ?
    "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/${each.value.roleDefinitionIdOrName}" :
    null
  )

  role_definition_name = (
    length(regexall("^/subscriptions/.+/providers/Microsoft.Authorization/roleDefinitions/.+$", each.value.roleDefinitionIdOrName)) == 0 &&
    length(regexall("^[0-9a-fA-F-]{36}$", each.value.roleDefinitionIdOrName)) == 0
  ) ? each.value.roleDefinitionIdOrName : null
}
