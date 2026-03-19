# Acknowledgments

BigDACLEnergy's design is inspired by the approaches and methodologies of the
following Active Directory security tools. No source code from these projects
has been incorporated into BigDACLEnergy — all code is an independent
implementation.

## ADeleg

- **Author:** [@mtth-bfft](https://github.com/mtth-bfft) (Matthieu Buffet)
- **Repository:** [mtth-bfft/adeleg](https://github.com/mtth-bfft/adeleg)
- **Description:** An Active Directory delegation management tool that
  inventories delegations in an AD forest by enumerating security descriptors
  and filtering out expected ACEs. ADeleg's approach to surfacing meaningful,
  non-inherited delegations was a key inspiration for BigDACLEnergy's analysis
  methodology.

## ADeleginator

- **Author:** [@techspence](https://github.com/techspence) (Spencer Alessi,
  Ethical Threat)
- **Repository:**
  [techspence/ADeleginator](https://github.com/techspence/ADeleginator)
- **Description:** A PowerShell-based companion tool to ADeleg that
  identifies insecure trustee and resource delegations in Active Directory.
  ADeleginator's approach to categorizing delegation risks against Tier 0
  assets inspired BigDACLEnergy's risk-scoring and reporting methodology.

---

We are grateful to both Matthieu Buffet and Spencer Alessi for their
contributions to the Active Directory security community. Their work made AD
delegation analysis more accessible and directly inspired this project.
