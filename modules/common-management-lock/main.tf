resource "azurerm_management_lock" "this" {
  count = var.lock == null ? 0 : 1

  name       = coalesce(var.lock.name, "lock-${var.name_suffix}")
  scope      = var.scope
  lock_level = var.lock.kind
  notes      = var.lock.notes
}
