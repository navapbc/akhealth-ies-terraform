terraform {
  backend "azurerm" {
    resource_group_name  = "rg-iep-wus2-dev-operations-01"
    storage_account_name = "stiepwus2devtf001"
    container_name       = "stc-iep-wus2-dev-tfstate-001"
    key                  = "main.dev.tfstate"
    use_azuread_auth     = true
  }
}
