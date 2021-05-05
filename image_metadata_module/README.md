# Image Metadata Analyzer 
Autopsy Module

## Installation
1. Install `exiftool` command-line tool by Phil Harvey from the [official website](https://exiftool.org/).
2. Install `jython` for the proper conversion of Python code into Java. You can install it from the [official website](https://www.jython.org/download).

Make sure to install `exiftool` in the proper *PATH*:
- **Windows**: `C:\WINDOWS\exiftool.exe`
- **MacOS**: `/usr/local/bin/exiftool`

## Image Metadata Filter
### Different levels:
- 1st level => basic one condition filter
- 2nd level => "AND" filter ("" + AND + "")
- 3rd level => "OR" filter ("" + OR + "")
- 4th level => "NOT" filter (NOT + "")
- 5th level => filter by specific metadata attribute (Author == Jordi)
- 6th level => filter by specific metadata attribute (Author != Jordi)
- 7th level => filter by specific metadata attribute (Author CONTAIN Jordi)
- 8th level => filter by specific metadata attribute (Author DOES NOT CONTAIN Jordi)
- TODO: 9th level => "AND", "OR", "NOT" mixed filter

 


