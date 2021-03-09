<p align="center">
	<img src="https://i.imgur.com/rfkOCSI.png"/>
</p>

GhidraQuark bridges Quark Engine into Ghidra.

Fire a Quark analysis or inspect program behaviors with Quark report. Work with Quark and Ghidra all at once!

## Demo

[![](https://i.imgur.com/CipAD0D.jpg)](https://www.youtube.com/watch?v=VXzfFB2S4bo&ab_channel=JunWeiSong)

## Installing the extension

+ Download the built extension from GitHub
  + Visit the Releases page, normally use the latest release
  + Download the built extension zip file `ghidra_9.2.2_PUBLIC_20210204_QuarkEngineHelper`
+ If you don't already have Ghdira, download and install Ghidra from https://ghidra-sre.org/
+ Install the extension into Ghidra
  + Start Ghidra
  + Open `File->Install Extensions...`
  + Press the `+` icon found in the top right of the `Install Extensions` window
  + Navigate to the file location where you downloaded the extension zip file above and select it
  + Press `OK`
  + You may want to restart Ghidra for the changes to take effect
  + Enjoy it!

## Building extension from the command line

+ Install Gradle

+ Execute the following commands

  ```
  $ gradle -PGHIDRA_INSTALL_DIR=<path_to_ghidra>
  ```

+ Zip file will be created in the `dist` folder

## Resources

### Ghidra

+ https://ghidra.re/online-courses/
+ https://ghidra.re/ghidra_docs/api/
+ https://github.com/edmcman/ghidra-scala-loader

---

Don't forget to take a glance at our [Quark-Engine](https://github.com/quark-engine/quark-engine) GitHub page :)
