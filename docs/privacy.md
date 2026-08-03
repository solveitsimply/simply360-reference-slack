# Privacy notice

This development reference app is limited to the dedicated synthetic
`Simply360 Developer Test` Slack workspace and Simply360 publisher test teams.
It processes reference-only event coordinates, explicitly submitted message
text, Slack channel/user coordinates, and the minimum OAuth credentials needed
for the installed proof.

No customer or production data is authorized. Secrets are not logged or
committed. Event payload fields are not forwarded to Slack; the event
destination posts an allowlisted summary. Local test doubles retain data only
for the lifetime of the test process. A deployed dev stack must delete
installation credentials and bounded operational state on uninstall.
