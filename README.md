# TP-Link JetStream switches component for Home Assistant

Home Assistant custom component for control TP-Link JetStream switches over LAN.

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![License](https://img.shields.io/github/license/gaaf/hass-tplink-jetstream)](https://github.com/gaaf/hass-tplink-jetstream/blob/master/LICENSE.md)
![Active installations](https://raw.githubusercontent.com/vmakeev/custom_badges_updater/main/tplink_jetstream.svg)

[![Release](https://img.shields.io/github/v/release/gaaf/hass-tplink-jetstream)](https://github.com/gaaf/hass-tplink-jetstream/releases/latest)
[![ReleaseDate](https://img.shields.io/github/release-date/gaaf/hass-tplink-jetstream)](https://github.com/gaaf/hass-tplink-jetstream/releases/latest)
![Maintained](https://img.shields.io/maintenance/yes/2023)

## Key features

- obtaining information about all ports:
  - connection status
  - actual connection speed
  - configured connection speed
  - Poe status
  - Poe details (priority, power limits, actual power/current/voltage, power delivery class)
- ports management:
  - enable or disable specific ports
  - setting PoE parameters on the specified ports (enable/disable, priority, power limits)
- obtaining hardware and firmware version of the switch
- obtaining information about total PoE consumption
- setting limits on total PoE consumption
- automatic detection of available functions

## Supported models

|                                          Name                                            |  Revision | Confirmed |           Notes                         |
|------------------------------------------------------------------------------------------|-----------|-----------|-----------------------------------------|
| [TL-SG2428P](https://www.tp-link.com/en/business-networking/omada-sdn-switch/tl-sg2428p/)    |   V1     |    Yes    | All features are available              |
| Other JetStream switches with web-based user interface                                  | --------- |    No     | Will most likely work

## Installation

### Manual

Copy `tplink_jetstream` folder from [latest release](https://github.com/gaaf/hass-tplink-jetstream/releases/latest) to `custom_components` folder in your Home Assistant config folder and restart Home Assistant. The final path to folder should look like this: `<home-assistant-config-folder>/custom_components/tplink_jetstream`.

### HACS

[Add a custom repository](https://hacs.xyz/docs/faq/custom_repositories/) `https://github.com/gaaf/hass-tplink-jetstream` with `Integration` category to [HACS](https://hacs.xyz/) and restart Home Assistant.

## Configuration

Configuration > [Integrations](https://my.home-assistant.io/redirect/integrations/) > Add Integration > [TP-Link JetStream](https://my.home-assistant.io/redirect/config_flow_start/?domain=tplink_jetstream)


### Advanced options

You can perform advanced component configuration by clicking the `CONFIGURE` button after adding it. 

![Integration](docs/images/integration.png)

Advanced settings include:
|                                          Name                                           |  Default   |
|-----------------------------------------------------------------------------------------|------------|
| Update interval                                                                         | 30 seconds |
| Enabling or disabling [port state switches](docs/controls.md#port-state-switch)         |  Disabled  |
| Enabling or disabling [port PoE state switches](docs/controls.md#port-poe-state-switch) |  Disabled  |


![Options 1/2](docs/images/options_1.png)

![Options 2/2](docs/images/options_2.png)

## Sensors

* Network information ([read more](docs/sensors.md#network-information))
* PoE consumption ([read more](docs/sensors.md#poe-consumption))

## Binary sensors

* Port status ([read more](docs/sensors.md#port-status))
* Port PoE status ([read more](docs/sensors.md#port-poe-status))


## Switches

* Port state ([read more](docs/controls.md#port-state-switch))
* Port PoE state ([read more](docs/controls.md#port-poe-state-switch))


## Services

* Set the PoE power limit ([read more](docs/services.md#set-the-poe-power-limit))
* Set PoE settings for a specific port ([read more](docs/services.md#set-poe-settings-for-a-specific-port))
