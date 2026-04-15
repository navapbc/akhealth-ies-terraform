import {
  to = azurerm_resource_group.solution["network"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004"
}

import {
  to = azurerm_resource_group.solution["networkEdge"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-edge-004"
}

import {
  to = azurerm_resource_group.solution["hosting"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-hosting-004"
}

import {
  to = azurerm_resource_group.solution["data"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-data-004"
}

import {
  to = azurerm_resource_group.solution["operations"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-operations-004"
}

import {
  to = module.app_insights.azurerm_application_insights.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-operations-004/providers/Microsoft.Insights/components/appi-iep-wus2-dev-004"
}

import {
  to = module.log_analytics_workspace[0].azurerm_log_analytics_workspace.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-operations-004/providers/Microsoft.OperationalInsights/workspaces/log-iep-wus2-dev-004"
}

import {
  to = module.app_service_plan[0].azurerm_service_plan.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-hosting-004/providers/Microsoft.Web/serverFarms/asp-iep-wus2-dev-004"
}

import {
  to = module.web_app.azurerm_windows_web_app.this[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-hosting-004/providers/Microsoft.Web/sites/app-iep-wus2-dev-004"
}

import {
  to = module.key_vault.azurerm_key_vault.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-operations-004/providers/Microsoft.KeyVault/vaults/kv-iep-wus2-dev-004"
}

import {
  to = module.postgresql[0].azurerm_postgresql_flexible_server.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-data-004/providers/Microsoft.DBforPostgreSQL/flexibleServers/psqlfx-iep-wus2-dev-postgresql-004"
}

import {
  to = module.postgresql[0].azurerm_postgresql_flexible_server_active_directory_administrator.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-data-004/providers/Microsoft.DBforPostgreSQL/flexibleServers/psqlfx-iep-wus2-dev-postgresql-004/administrators/b58ff011-4384-42b9-b25c-26c5dfc26b06"
}

import {
  to = module.postgresql[0].azurerm_postgresql_flexible_server_database.this["appdb"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-data-004/providers/Microsoft.DBforPostgreSQL/flexibleServers/psqlfx-iep-wus2-dev-postgresql-004/databases/appdb"
}

import {
  to = module.network.azurerm_virtual_network.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/virtualNetworks/vnet-iep-wus2-dev-004"
}

import {
  to = module.network.azurerm_network_security_group.appsvc[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/networkSecurityGroups/nsg-iep-wus2-dev-appservice-004"
}

import {
  to = module.network.azurerm_network_security_group.private_endpoint[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/networkSecurityGroups/nsg-iep-wus2-dev-privateendpoint-004"
}

import {
  to = module.network.azurerm_network_security_group.postgresql[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/networkSecurityGroups/nsg-iep-wus2-dev-postgresql-004"
}

import {
  to = module.network.azurerm_subnet.app_service
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/virtualNetworks/vnet-iep-wus2-dev-004/subnets/snet-iep-wus2-dev-appservice-004"
}

import {
  to = module.network.azurerm_subnet.private_endpoint[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/virtualNetworks/vnet-iep-wus2-dev-004/subnets/snet-iep-wus2-dev-privateendpoint-004"
}

import {
  to = module.network.azurerm_subnet.postgresql[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/virtualNetworks/vnet-iep-wus2-dev-004/subnets/snet-iep-wus2-dev-postgresql-004"
}

import {
  to = module.network.azurerm_subnet_network_security_group_association.app_service
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/virtualNetworks/vnet-iep-wus2-dev-004/subnets/snet-iep-wus2-dev-appservice-004"
}

import {
  to = module.network.azurerm_subnet_network_security_group_association.private_endpoint[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/virtualNetworks/vnet-iep-wus2-dev-004/subnets/snet-iep-wus2-dev-privateendpoint-004"
}

import {
  to = module.network.azurerm_subnet_network_security_group_association.postgresql[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/virtualNetworks/vnet-iep-wus2-dev-004/subnets/snet-iep-wus2-dev-postgresql-004"
}

import {
  to = module.key_vault.azurerm_private_dns_zone.default[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
}

import {
  to = module.key_vault.azurerm_private_dns_zone_virtual_network_link.default["vnet-iep-wus2-dev-004"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net/virtualNetworkLinks/vnet-iep-wus2-dev-004"
}

import {
  to = module.key_vault.azurerm_private_endpoint.default[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/privateEndpoints/pep-iep-wus2-dev-keyvault-004"
}

import {
  to = module.web_app.azurerm_private_dns_zone.default[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/privateDnsZones/privatelink.azurewebsites.net"
}

import {
  to = module.web_app.azurerm_private_dns_zone_virtual_network_link.default["vnet-iep-wus2-dev-004"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/privateDnsZones/privatelink.azurewebsites.net/virtualNetworkLinks/vnet-iep-wus2-dev-004"
}

import {
  to = module.web_app.azurerm_private_endpoint.default[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/privateEndpoints/pep-iep-wus2-dev-appservice-004"
}

import {
  to = module.postgresql[0].azurerm_private_dns_zone.this[0]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/privateDnsZones/pdz-iep-wus2-dev-postgresql-004.postgres.database.azure.com"
}

import {
  to = module.postgresql[0].azurerm_private_dns_zone_virtual_network_link.this["vnet-iep-wus2-dev-004"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/privateDnsZones/pdz-iep-wus2-dev-postgresql-004.postgres.database.azure.com/virtualNetworkLinks/vnet-iep-wus2-dev-004"
}

import {
  to = module.front_door_waf_policy[0].azurerm_cdn_frontdoor_firewall_policy.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-edge-004/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/fdfpiepglobaldev004"
}

import {
  to = module.front_door[0].azurerm_cdn_frontdoor_profile.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-edge-004/providers/Microsoft.Cdn/profiles/afd-iep-global-dev-004"
}

import {
  to = module.front_door[0].azurerm_cdn_frontdoor_endpoint.this["default"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-edge-004/providers/Microsoft.Cdn/profiles/afd-iep-global-dev-004/afdEndpoints/fde-iep-global-dev-default-004"
}

import {
  to = module.front_door[0].azurerm_cdn_frontdoor_origin_group.this["app-default"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-edge-004/providers/Microsoft.Cdn/profiles/afd-iep-global-dev-004/originGroups/app-default"
}

import {
  to = module.front_door[0].azurerm_cdn_frontdoor_origin.this["app-default/app-default"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-edge-004/providers/Microsoft.Cdn/profiles/afd-iep-global-dev-004/originGroups/app-default/origins/app-default"
}

import {
  to = module.front_door[0].azurerm_cdn_frontdoor_route.this["default/default"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-edge-004/providers/Microsoft.Cdn/profiles/afd-iep-global-dev-004/afdEndpoints/fde-iep-global-dev-default-004/routes/default"
}

import {
  to = module.front_door_security_policy[0].azurerm_cdn_frontdoor_security_policy.this
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-edge-004/providers/Microsoft.Cdn/profiles/afd-iep-global-dev-004/securityPolicies/fdsecp-iep-wus2-dev-004"
}

import {
  to = module.network.module.nsg_diagnostic_settings["nsg-iep-wus2-dev-appservice-004"].azurerm_monitor_diagnostic_setting.this["nsg-iep-wus2-dev-appservice-004-diagnosticSettings"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/networkSecurityGroups/nsg-iep-wus2-dev-appservice-004|nsg-iep-wus2-dev-appservice-004-diagnosticSettings"
}

import {
  to = module.network.module.nsg_diagnostic_settings["nsg-iep-wus2-dev-postgresql-004"].azurerm_monitor_diagnostic_setting.this["nsg-iep-wus2-dev-postgresql-004-diagnosticSettings"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/networkSecurityGroups/nsg-iep-wus2-dev-postgresql-004|nsg-iep-wus2-dev-postgresql-004-diagnosticSettings"
}

import {
  to = module.network.module.nsg_diagnostic_settings["nsg-iep-wus2-dev-privateendpoint-004"].azurerm_monitor_diagnostic_setting.this["nsg-iep-wus2-dev-privateendpoint-004-diagnosticSettings"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourceGroups/rg-iep-wus2-dev-network-004/providers/Microsoft.Network/networkSecurityGroups/nsg-iep-wus2-dev-privateendpoint-004|nsg-iep-wus2-dev-privateendpoint-004-diagnosticSettings"
}

import {
  to = module.postgresql[0].module.role_assignments.azurerm_role_assignment.this["app-service-reader"]
  id = "/subscriptions/dec9c331-d773-4f77-a5a8-39e95699c4a5/resourcegroups/rg-iep-wus2-dev-data-004/providers/Microsoft.DBforPostgreSQL/flexibleServers/psqlfx-iep-wus2-dev-postgresql-004/providers/Microsoft.Authorization/roleAssignments/4d8e3754-35a0-52e4-b131-4239113ddfb7"
}
