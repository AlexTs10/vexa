# vexa-daemon Python helpers

- `native_group.py`: runs several services in one Python process (the `core` and `agent` groups).
- `native_launch.py`: runs crm-api and model-proxy alone on loopback and a given port; makes the connection keys.
- `merge_groups.py`: writes the locked project of each process group (`groups/`).
- `group_env_check.py`: lists the settings that leak from one core member to another (input: `vexa-daemon specs`).
