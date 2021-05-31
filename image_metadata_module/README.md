# Image Metadata Analyzer Module 
Autopsy Module by Jordi Domenech (jordidomenech99@gmail.com)

## Installation
1. Install `exiftool` command-line tool by Phil Harvey from the [official website](https://exiftool.org/).
2. Install `jython` for the proper conversion of Python code into Java. You can install it from the [official website](https://www.jython.org/download).
3. Download this repository and copy the `image_metadata_module` folder in *Tools > Python Modules* section of Autopsy.

Make sure to install `exiftool` in the proper *PATH*:
- **Windows**: `C:\WINDOWS\exiftool.exe`
- **MacOS**: `/usr/local/bin/exiftool`

## Image Metadata Filter


| Filter Type          | Text Pattern                            | Description                                                                                                                                 |
|:-------------------- |:--------------------------------------- |:------------------------------------------------------------------------------------------------------------------------------------------- |
| **Simple**           | Name1                                   | Simple filter.  The module searches if the word is in the metadata of any image analyzed in the case                                        |
| **NOT**              | **NOT** Name1                           | NOT filter. The module searches if the word is NOT in the metadata of any image analyzed in the case                                        |
| **AND**              | Name1 **AND** Name2 **AND** ...         | AND filter. The module searches if all the words are inside the metadata of any image                                                       |
| **OR**               | Name1 **OR** Name2 **OR** ...           | OR filter. The module searches if at least one of the words is inside the metadata of any image                                             |
| **==**               | MetadataTag **==** MetadataValue        | Filter by specific metadata tag and value. The module searches if a specific metadata value is inside any image                             |
| **!=**               | MetadataTag **!=** MetadataValue        | Filter by specific metadata tag and value. The module searches if a specific metadata value is NOT inside any image                         |
| **CONTAINS**         | MetadataTag **CONTAINS** Name           | Filter by specific metadata tag. The module searches if any image contains the word in the metadata value of a specific MetadataTag         | 
| **DOES NOT CONTAIN** | MetadataTag **DOES NOT CONTAIN** Name   | Filter by specific metadata tag. The module searches if any image does NOT contain the word in the metadata value of a specific MetadataTag |


**CAUTION:** The MetadataTag must match perfectly accordingly to the [Exiftool Tag Names](https://exiftool.org/TagNames/).

If you have more doubts about the installation and/or the functioning of the module download the [TFG.pdf] file (../TFG_test.pdf) or contact me via email.

