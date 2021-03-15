import exiftool

while (True):
    try:
        print("Introduce the name of an image to analyze its metadata: ")

        file = input()

        # Extract image metadata from the file
        with exiftool.ExifTool() as et:
            metadata = et.get_metadata(file)
        
        break
    
    except ValueError:
        print("Error: File not found!")


# Print all the metadata
for m in range(0, len(metadata)):
    print(list(metadata)[m],list(metadata.values())[m])

#exif_iptc_metadata = metadata

# Extract File information, EXIF and IPTC metadata
#for n in list(exif_iptc_metadata):
#    if not (n.startswith("File") or n.startswith("EXIF") or n.startswith("IPTC")):
#        exif_iptc_metadata.pop(n)
    
# Print File information, EXIF and IPTC metadata
#for m in range(0, len(exif_iptc_metadata)):
#    print(list(exif_iptc_metadata)[m],list(exif_iptc_metadata.values())[m])



