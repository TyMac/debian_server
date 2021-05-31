# Packer Debian server template to assist with "PCI-DSS" compliance.

This Packer build helps provide a base configuration for PCI-DSS Requirement 2.2.

Uses the [chef-os-hardening](https://github.com/dev-sec/chef-os-hardening) cookbook under the [Apache 2.0 License](https://github.com/dev-sec/chef-os-hardening/blob/master/LICENSE) from the [DevSec Hardening Framework ](https://github.com/dev-sec)

Does not include antivirus required by PCI-DSS Requirement 5.

Does not imply or guarantee PCI compliance, but should help put you on the correct path for configuration standards.
