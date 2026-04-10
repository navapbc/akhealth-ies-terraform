moved {
  from = module.postgresql[0].module.role_assignments.azurerm_role_assignment.this["0"]
  to   = module.postgresql[0].module.role_assignments.azurerm_role_assignment.this["app-service-reader"]
}
