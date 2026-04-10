resource "azurerm_management_lock" "this" {
  count = (
    var.lock == null ||
    try(var.lock.kind, null) == null ||
    try(var.lock.kind, "None") == "None"
  ) ? 0 : 1

  name       = coalesce(try(var.lock.name, null), "lock-${var.name_suffix}")
  scope      = var.scope
  lock_level = var.lock.kind
  notes      = try(var.lock.notes, null)
}
