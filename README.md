# binja-xtensa: Architecture Plugin and ESP8266 Loader

Tensilica Xtensa Architecture Plugin and ESP8266 Firmware Loader for Binary
Ninja.

![screenshot of Binary Ninja showing setup and loop of a decompiled ESP8266
Arduino project](https://raw.githubusercontent.com/zackorndorff/binja-xtensa/0.5/screenshots/hero.png)

This is a fork of the original project created by @zackorndorff : https://github.com/zackorndorff/binja-xtensa
This work was done as a Master Semester project at EPFL, Lausanne, together 
with the Cyber-Defence Campus, supervised by Daniel Hulliger.

Goal of this project is to create a usable plugin with full functionality 
for XTensa Architecture, implementing features left out by the original author.

For a quick overview of the Xtensa ISA, I recommend [Espressif's overview](https://dl.espressif.com/github_assets/espressif/xtensa-isa-doc/releases/download/latest/Xtensa.pdf).

## Features

* Disassembly of almost all Xtensa instructions, except for the MAC16 option instructions 
* Lifting for most Xtensa instructions, except for the MAC16 option instructions 
  and a few instructions noted in Lists/Lifted_instr_list
* Support for Xtensa ELF files so they will be automatically recognized
* Loader for ESP8266 raw firmware dumps. This support is a little finicky to
  use, as there's multiple partitions in the firmware dumps. By default it uses
  the last one with a detected header; you can adjust this via Open With
  Options
    * At the moment it doesn't completely map the sections properly, but it's a
      start :)

## What it doesn't do

* Anything with the optional vector unit (MAC16)
* Anything quickly. This is Python, and not particularly well optimized Python
  at that. If you're using this seriously, I recommend rewriting in C++
* Find `main` in a raw binary for you

## Installation

Install via the Binary Ninja plugin manager. Alternatively, clone this
repository into your Binary Ninja plugins directory. See the [official Binary
Ninja documentation](https://docs.binary.ninja/guide/plugins.html) for more
details.

# Plugin structure:
 * __init__.py: registers architecture, sets up reg names & control-flow instructions
 * binaryview.py: defines the ESP8266 Firmware for the loader
 * instruction.py: defines instruction formats, decoding rules
 * disassemble.py: uses format information to tokenize and print disassembled instructions
 * lifter.py: actual lifting logic to LLIL

## Using the ESP8266 Firmware Loader

The default of picking the last usable partition works decent, but if you want
more control, use Open With Options and change `Loader > Which Firmware` to the
option corresponding to the address you want to load.

I attempt to load in symbols from the SDK's linker script so some of the
ROM-implemented functions are less mysterious. See
[parse_rom_ld.py](binja_xtensa/parse_rom_ld.py) for the parsing code,
[known_symbols.py](binja_xtensa/known_symbols.py) for the database it'll apply,
and function `setup_esp8266_map` in
[binaryview.py](binja_xtensa/binaryview.py#L17) for the code that applies it.
This should probably be a load time option... but it's not at the moment :/

![screenshot of Binary Ninja's Open With Options showing the Loader Which
Firmware option](https://raw.githubusercontent.com/zackorndorff/binja-xtensa/0.5/screenshots/open-with-options.png)


## Evaluation

To check the amount of disassembled opcodes or unlifted instructions, you can use 
the [evaluation.py](binja_xtensa/evaluation/evaluation.py) script. This loads all
binaries in a target folder, including contents of archive .a files, and runs the
Binary Ninja analysis. The results are then stored in a target path provided to the
script. This helped with checking the progress during the implementation and understand
which instructions should take priority when lifting. For visualizing the results,
you can use the plotter in [plotter.ipynb](binja_xtensa/evaluation/plotter.ipynb) 

## Testing

There are some simple tests in
[test_instruction.py](binja_xtensa/test_instruction.py), which are mostly just
taking uniq'd output from objdump on some binaries I had laying around and
making sure the output matches. They can be run with `python -m pytest` from the
root of the project.

## Future Work

* Improve lifters once additional Binary Ninja features are added:
    * Loop Option: function-level lifting necessary to lift loops that span multiple basic blocks.
    * Windowed Registers: Transparent copies would help higher level analysis
* Cleanly implement LITBASE offset, using loading options
    * More information: Daniel Wegemer's [presentation](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Daniel%20Wegemer%20-%20Unlocking%20hidden%20powers%20in%20Xtensa%20based%20Qualcomm%20Wifi%20chips.pdf) at DEFCON31
* Add MAC16 option lifters
* Proper Flag usage when lifting instructions
* Improve the raw firmware loader
* Improve section classifications (e.g. currently .literal is seen as code instead of data)
* Rewrite to be faster

## License

This project copyright Nicolae Binica (@nicabi) and Zack Orndorff (@zackorndorff) and is available under the
MIT license. See [LICENSE](LICENSE).
