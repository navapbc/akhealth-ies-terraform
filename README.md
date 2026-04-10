# akhealth-ies-terraform

Terraform translation of the `akhealth-ies-bicep` solution template set using AzureRM-first resources and a module layout that follows the major Bicep composition boundaries.

## Layout

- `main.tf`, `variables.tf`, `locals.tf`, `outputs.tf`: translated root deployment.
- `modules/`: reusable Terraform modules for networking, monitoring, app hosting, secrets, edge, and data services.
- `environments/main.dev.tfvars`: translation of `params/main.dev.bicepparam`.

## Usage

```bash
terraform init
terraform plan -var-file=environments/main.dev.tfvars
```

## Notes

- The root input objects intentionally stay close to the original Bicep parameter shapes to make migration easier.
- The provided `main.dev.tfvars` tracks the source dev parameters, with one practical change: PostgreSQL version is set to `16` for Terraform provider compatibility checks.
- Some advanced optional branches from the Bicep repo, especially less-common App Service and Application Gateway permutations, are represented in Terraform but were not exercised by the translated dev environment.
