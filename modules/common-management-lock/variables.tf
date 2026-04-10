variable "scope" {
  type = string
}

variable "name_suffix" {
  type = string
}

variable "lock" {
  type = object({
    kind  = string
    name  = optional(string)
    notes = optional(string)
  })
  default = null

  validation {
    condition = var.lock == null || contains([
      "CanNotDelete",
      "ReadOnly",
    ], var.lock.kind)
    error_message = "lock.kind must be CanNotDelete or ReadOnly when a lock is provided."
  }
}
