terraform {
  backend "azurerm" {
    resource_group_name  = "rg-iep-eus-dev-operations-01"
    storage_account_name = "stiepeusdevtf001"
    container_name       = "stc-iep-eus-dev-tfstate-001"
    key                  = "main.dev.tfstate"
    use_azuread_auth     = true
  }
}
