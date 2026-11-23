resource "azurerm_storage_account" "docs" {
  name     = "shopdocs"
  location = "centralindia"
}

locals {
  location = "checkout"
}
