# binja-xtensa: Architecture Plugin and ESP8266 Loader

Tensilica Xtensa Architecture Plugin and ESP8266 Firmware Loader for Binary
Ninja.

This is a fork of the original project created by @zackorndorff : https://github.com/zackorndorff/binja-xtensa

Goal of this project is to create a usable plugin with full functionality for XTensa Architecture, implementing functionalities left out by the original author.

Milestones:
  - Get environment setup, able to run the plugin. analyze code to find performance bottlenecks, lack of implementation for features and bugs: 2 weeks
  - Verify if ISA is fully implemented. Add missing instructions. 3 weeks
  - Implement missing LLIL (Low Level Intermediate Language) lifting. All supported xtensa instructions should be lifted to the Binary Ninja Intermediate Language 3 weeks
  - implement special registers mentioned by the author of the plugin. 3 weeks
  - implement other quality of life features: help you find `main` in a raw binary etc. : 2 weeks
  - test/benchmark? plugin to find further bugs and performance issues 2 weeks

