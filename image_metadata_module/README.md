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
- 1st level => basic one condition filter (ex: iPhone)
- 2nd level => `AND` filter (ex: Canon `AND` Jordi)
- 3rd level => `OR` filter (ex: iPhone `OR` Canon)
- 4th level => `NOT` filter (ex: `NOT` Canon)
- 5th level => filter `==` by specific metadata tag and value (ex: Author `==` Jordi)
- 6th level => filter `!=` by specific metadata tag and value (ex: Author `!=` Jordi)
- 7th level => filter `CONTAINS` by specific metadata tag (ex: Author `CONTAINS` Jordi)
- 8th level => filter `DOES NOT CONTAIN` by specific metadata tag (ex: Author `DOES NOT CONTAIN` Jordi)


| Filter Type          | Text Pattern                                     | Description                                                                                                |
|:-------------------- |:------------------------------------------------ |:---------------------------------------------------------------------------------------------------------- |
| **Simple**           | Name1                                            | The module searches if the word is in the metadata of any image analyzed in the case                       |
| **NOT**              | **NOT** Name1                                    | The module searches if the word is NOT in the metadata of any image analyzed in the case                   |
| **AND**              | Name1 **AND** Name2 **AND** ...                  | The module searches if all the words are inside the metadata of any image                                  |
| **OR**               | Name1 **OR** Name2 **OR** ...                    | The module searches if at least one of the words is inside the metadata of any image                       |
| **==**               | MetadataTag1 **==** MetadataValue1               | The module searches if a specific metadata value is inside any image                                       |
| **!=**               | MetadataTag1 **!=** MetadataValue1               | The module searches if a specific metadata value is NOT inside any image                                   |
| **CONTAINS**         | MetadataTag1 **CONTAINS** MetadataValue1         | The module searches if any image contains the word in the metadata value of a specific MetadataTag         | 
| **DOES NOT CONTAIN** | MetadataTag1 **DOES NOT CONTAIN** MetadataValue1 | The module searches if any image does NOT contain the word in the metadata value of a specific MetadataTag |
