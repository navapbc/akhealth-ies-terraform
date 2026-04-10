variable "scope" {
  type = string
}

variable "role_assignments" {
  type    = list(any)
  default = []
}
