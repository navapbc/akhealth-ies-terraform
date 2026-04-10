moved {
  from = module.network.module.nsg_diagnostic_settings["nsg-iep-eus2-dev-appservice-002"].azurerm_monitor_diagnostic_setting.this["0"]
  to   = module.network.module.nsg_diagnostic_settings["nsg-iep-eus2-dev-appservice-002"].azurerm_monitor_diagnostic_setting.this["nsg-iep-eus2-dev-appservice-002-diagnosticSettings"]
}

moved {
  from = module.network.module.nsg_diagnostic_settings["nsg-iep-eus2-dev-postgresql-002"].azurerm_monitor_diagnostic_setting.this["0"]
  to   = module.network.module.nsg_diagnostic_settings["nsg-iep-eus2-dev-postgresql-002"].azurerm_monitor_diagnostic_setting.this["nsg-iep-eus2-dev-postgresql-002-diagnosticSettings"]
}

moved {
  from = module.network.module.nsg_diagnostic_settings["nsg-iep-eus2-dev-privateendpoint-002"].azurerm_monitor_diagnostic_setting.this["0"]
  to   = module.network.module.nsg_diagnostic_settings["nsg-iep-eus2-dev-privateendpoint-002"].azurerm_monitor_diagnostic_setting.this["nsg-iep-eus2-dev-privateendpoint-002-diagnosticSettings"]
}
