terraform {
  required_version = "~> 1.5"

  backend "azurerm" {
    use_azuread_auth     = true
    tenant_id            = "ba06645f-e0cc-44b5-897f-34eb6aa59588"
    subscription_id      = "dec9c331-d773-4f77-a5a8-39e95699c4a5"
    storage_account_name = "tfstfef5519ba84acf90f6f7"
    container_name       = "backends"
    key                  = "private/main.tfstate"
  }
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
  subscription_id = "dec9c331-d773-4f77-a5a8-39e95699c4a5"
  tenant_id       = "ba06645f-e0cc-44b5-897f-34eb6aa59588"
}
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//START: Shared Resources
data "azurerm_client_config" "current" {}

# This ensures we have unique CAF compliant names for our resources.
module "naming" {
  source  = "Azure/naming/azurerm"
  version = "0.3.0"
}

resource "azurerm_resource_group" "defaultResourceGroup" {
  location = "eastus"
  name     = module.naming.resource_group.name_unique
}

resource "azurerm_virtual_network" "defaultVirtualNetwork" {
  location            = azurerm_resource_group.defaultResourceGroup.location
  name                = module.naming.virtual_network.name_unique
  resource_group_name = azurerm_resource_group.defaultResourceGroup.name
  address_space       = ["10.0.0.0/21"]
}
//END: Shared Resources
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//START: PGSQL and PGSQL Dependency Creation
# This ensures we have unique CAF compliant names for our resources.
module "pgsqlNaming" {
  source  = "Azure/naming/azurerm"
  version = "0.3.0"
}

resource "azurerm_subnet" "pgsqlSubnet" {
  address_prefixes                = ["10.0.1.0/25"]
  name                            = module.pgsqlNaming.subnet.name_unique
  resource_group_name             = azurerm_resource_group.defaultResourceGroup.name
  virtual_network_name            = azurerm_virtual_network.defaultVirtualNetwork.name
  default_outbound_access_enabled = false

  delegation {
    name = "delegation"

    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

/*resource "azurerm_private_dns_zone" "pgsqlPrivateDNSZone" {
  name                = "private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.defaultResourceGroup.name
}*/

resource "azurerm_postgresql_flexible_server" "pgsqlFlexibleServer" {
  depends_on          = [azurerm_subnet.pgsqlSubnet]
  location            = "eastus"
  name                = "psql-sys-dev-eus-001-test6"
  resource_group_name = azurerm_resource_group.defaultResourceGroup.name
  zone                = 1
  //private_dns_zone_id = azurerm_private_dns_zone.pgsqlPrivateDNSZone.id
  identity {
    type         = "SystemAssigned"
    identity_ids = []
  }
  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = "ba06645f-e0cc-44b5-897f-34eb6aa59588"

  }
  //delegated_subnet_id = azurerm_subnet.pgsqlSubnet.id
  public_network_access_enabled = true

  sku_name = "B_Standard_B1ms"

  storage_mb   = "131072"
  storage_tier = "P10"

  version = 16
}

/*resource "azurerm_role_assignment" "pgsqlOwner" {
  scope                = azurerm_postgresql_flexible_server.pgsqlFlexibleServer.id
  role_definition_name = "Owner"
  principal_id         = "ecd5bf2d-f15c-44d1-8420-529d7c45e88b" //secgrp-akies-dev-dbadmin-001
  principal_type       = "Group"
}*/

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "pgsqlAdmin" {
  depends_on          = [azurerm_postgresql_flexible_server.pgsqlFlexibleServer]
  tenant_id           = "ba06645f-e0cc-44b5-897f-34eb6aa59588"
  server_name         = azurerm_postgresql_flexible_server.pgsqlFlexibleServer.name
  resource_group_name = azurerm_resource_group.defaultResourceGroup.name
  principal_type      = "Group"
  principal_name      = "secgrp-akies-dev-dbadmin-001"
  object_id           = "ecd5bf2d-f15c-44d1-8420-529d7c45e88b" //secgrp-akies-dev-dbadmin-001
}
//END: PGSQL and PGSQL Dependency Creation
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//START: ACR and ACR Dependency Creation
resource "azurerm_private_dns_zone" "this" {
  name                = "privatelink.azurecr.io"
  resource_group_name = azurerm_resource_group.defaultResourceGroup.name
}

resource "azurerm_container_registry" "this" {
  location                      = "eastus"
  name                          = "acrsysdev001"
  resource_group_name           = azurerm_resource_group.defaultResourceGroup.name
  sku                           = "Premium" //required for private networking configs
  public_network_access_enabled = false
  identity {
    type         = "SystemAssigned"
    identity_ids = []
  }
}

resource "azurerm_role_assignment" "acrDataPlanPush" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPush"
  principal_id         = "ecd5bf2d-f15c-44d1-8420-529d7c45e88b" //secgrp-akies-dev-acradmin-001
  principal_type       = "Group"
}

resource "azurerm_role_assignment" "acrDataPlanDelete" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrDelete"
  principal_id         = "ecd5bf2d-f15c-44d1-8420-529d7c45e88b" //secgrp-akies-dev-acradmin-001
  principal_type       = "Group"
}

resource "azurerm_role_assignment" "acrControlPlanRole" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "Container Registry Contributor and Data Access Configuration Administrator"
  principal_id         = "ecd5bf2d-f15c-44d1-8420-529d7c45e88b" //secgrp-akies-dev-acradmin-001
  principal_type       = "Group"
}

//END: ACR and ACR Dependency Creation
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//START: ACI and ACI Dependency Creation
resource "azurerm_subnet" "containerGroupSubnet" {
  address_prefixes                = ["10.0.0.128/25"]
  name                            = module.naming.subnet.name_unique
  resource_group_name             = azurerm_resource_group.defaultResourceGroup.name
  virtual_network_name            = azurerm_virtual_network.defaultVirtualNetwork.name
  default_outbound_access_enabled = true
  depends_on                      = [azurerm_virtual_network.defaultVirtualNetwork]

  delegation {
    name = "delegation"

    service_delegation {
      name    = "Microsoft.ContainerInstance/containerGroups"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

resource "azurerm_log_analytics_workspace" "defaultLogAnalyticsWorkspace" {
  location                   = azurerm_resource_group.defaultResourceGroup.location
  name                       = module.naming.log_analytics_workspace.name_unique
  resource_group_name        = azurerm_resource_group.defaultResourceGroup.name
  internet_ingestion_enabled = false
  internet_query_enabled     = false
  sku                        = "PerGB2018"
}

resource "azurerm_key_vault" "keyvault" {
  location                      = azurerm_resource_group.defaultResourceGroup.location
  name                          = module.naming.key_vault.name_unique
  resource_group_name           = azurerm_resource_group.defaultResourceGroup.name
  sku_name                      = "standard"
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  public_network_access_enabled = true
  rbac_authorization_enabled    = true
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = ["208.190.199.195"]
  }
}

//this block gives permissions to the current identity (user, service, or managed identity)
resource "azurerm_role_assignment" "current" {
  principal_id         = data.azurerm_client_config.current.object_id
  scope                = azurerm_key_vault.keyvault.id
  role_definition_name = "Key Vault Administrator"
}

resource "azurerm_role_assignment" "kvAdminGroupAssignment" {
  principal_id         = "58a9a684-f823-43b2-ab5f-9025a3bb2e06" //secgrp-akies-dev-kvadmin-001
  principal_type       = "Group"
  scope                = azurerm_key_vault.keyvault.id
  role_definition_name = "Key Vault Administrator"
}

resource "azurerm_role_assignment" "kvDataAccessAdminGroupAssignment" {
  principal_id         = "58a9a684-f823-43b2-ab5f-9025a3bb2e06" //secgrp-akies-dev-kvadmin-001
  principal_type       = "Group"
  scope                = azurerm_key_vault.keyvault.id
  role_definition_name = "Key Vault Data Access Administrator"
}

resource "azurerm_key_vault_secret" "secret" {
  key_vault_id    = azurerm_key_vault.keyvault.id
  name            = "secretname"
  expiration_date = "2026-12-30T20:00:00Z"
  value           = "password123"

  depends_on = [azurerm_role_assignment.current]
}

resource "azurerm_container_group" "containerGroupInstance" {
  depends_on          = []
  location            = "eastus"
  name                = module.naming.container_group.name_unique
  os_type             = "Linux"
  resource_group_name = azurerm_resource_group.defaultResourceGroup.name
  ip_address_type     = "Private"
  priority            = "Regular"
  restart_policy      = "Always"
  subnet_ids          = ["${azurerm_subnet.containerGroupSubnet.id}"]
  tags                = {}
  zones               = ["1"]
  dns_name_label_reuse_policy = "Unsecure"

  container {

    name   = "container1"
    image  = "public.ecr.aws/docker/library/nginx:latest"
    cpu    = 1
    memory = 2

    environment_variables        = { "ENVIRONMENT" = "dev" }
    secure_environment_variables = { "SECENV" = "avmpoc" }

    ports {
      port     = 80
      protocol = "TCP"
    }

    volume {
      mount_path = "/etc/secrets"
      name       = "secret1"
      secret = {
        "password" = base64encode("password123")
      }
    }

    volume {
      mount_path = "/usr/share/nginx/html"
      name       = "nginx"
      secret = {
        "indexpage" = base64encode("Hello, World!")
      }
    }
  }



  diagnostics {
    log_analytics {
      workspace_id  = azurerm_log_analytics_workspace.defaultLogAnalyticsWorkspace.workspace_id
      workspace_key = azurerm_log_analytics_workspace.defaultLogAnalyticsWorkspace.primary_shared_key
    }
  }

  exposed_port {
    port     = "80"
    protocol = "TCP"
  }

  identity {
    type = "SystemAssigned"
  }

  //to be defined
  /*image_registry_credential {
      server                    = image_registry_credential.value.server
      password                  = image_registry_credential.value.password
      user_assigned_identity_id = image_registry_credential.value.user_assigned_identity_id
      username                  = image_registry_credential.value.username
    }*/


  timeouts {
    create = "2h"
    update = "2h"
  }
}

resource "azurerm_role_assignment" "defaultContainerInstanceRoleAssignment" {
  principal_id         = data.azurerm_client_config.current.object_id
  scope                = azurerm_container_group.containerGroupInstance.id
  role_definition_name = "Contributor"
}



//END: ACI and ACI Dependency Creation
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////


