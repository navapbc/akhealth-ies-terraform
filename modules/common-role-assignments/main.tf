locals {
  assignments = {
    for index, assignment in var.role_assignments :
    coalesce(assignment.key, assignment.name, tostring(index)) => assignment
  }
}

resource "azurerm_role_assignment" "this" {
  for_each = local.assignments

  scope                                  = var.scope
  principal_id                           = each.value.principalId
  principal_type                         = each.value.principalType
  description                            = each.value.description
  condition                              = each.value.condition
  condition_version                      = each.value.conditionVersion
  delegated_managed_identity_resource_id = each.value.delegatedManagedIdentityResourceId
  name                                   = each.value.name
  role_definition_id                     = each.value.roleDefinitionId
  role_definition_name                   = each.value.roleDefinitionName
}
