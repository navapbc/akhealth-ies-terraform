 terraform {  
    backend "azurerm" {
    use_azuread_auth     = true
    tenant_id            = "ba06645f-e0cc-44b5-897f-34eb6aa59588"
    subscription_id      = "dec9c331-d773-4f77-a5a8-39e95699c4a5"
    storage_account_name = "tfstfef5519ba84acf90f6f7"
    container_name       = "backends"
    key                  = "private/main.tfstate"
  }
}
