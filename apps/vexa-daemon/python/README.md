# vexa-daemon Python helpers

- `native_group.py`: runs several services in one Python process (the `edge` and `agent` groups).
- `native_launch.py`: runs crm-api and model-proxy on loopback and a given port; makes the connection keys.
- `merge_groups.py`: writes the locked project of each process group (`groups/`).
