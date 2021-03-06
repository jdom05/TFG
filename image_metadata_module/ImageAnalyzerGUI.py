#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 30 09:16:46 2021

@author: JORDI
"""

# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.


# Ingest module for Autopsy with GUI
#
# Difference between other modules in this folder is that it has a GUI
# for user options.  This is not needed for very basic modules. If you
# don't need a configuration UI, start with the other sample module.
#
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/4.6.0/index.html for documentation


import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from java.awt import Panel, BorderLayout, EventQueue, GridLayout, GridBagLayout, GridBagConstraints, Font, Color, CardLayout, Component, FlowLayout, Dimension
from javax.swing import JFrame, JLabel, JButton, JTextField, JComboBox, JTextField, JProgressBar, JMenuBar, JMenuItem, JTabbedPane, JPasswordField, JCheckBox, SwingConstants, BoxLayout, JPanel, JScrollPane
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestModuleGlobalSettingsPanel
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from java.lang import IllegalArgumentException

from neededLib.exiftool import ExifTool
from neededLib import ImageAnalyzerLib
import re

PATH_WINDOWS = "C:\WINDOWS\exiftool.exe" # WINDOWS path to the exiftool executable
PATH_MACOS = "/usr/local/bin/exiftool" # MACOS path to the exiftool executable

filterCounter = 0
imageFound = False


#============================================================================================================#
#                              -- MODULE'S BASIC CONFIGURATION RELATED CLASS --                              #
#============================================================================================================#

class ImageMetadataFileIngestModuleWithUIFactory(IngestModuleFactoryAdapter):
    
    def __init__(self):
        self.settings = None

    # Give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Image Metadata Analyzer Module"

    def getModuleDisplayName(self):
        return self.moduleName

    # Give it a description
    def getModuleDescription(self):
        return "Autopsy module for automated analysis of image metadata."

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()
    
    
    #=========================== start of Panel GUI basic configuration methods ===============================#
    
    # Keep enabled only if you need ingest job-specific settings UI
    def hasIngestJobSettingsPanel(self):
        return True

    # Note that you must use GenericIngestModuleJobSettings instead of making a custom settings class.
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return ImageMetadataFileIngestModuleWithUISettingsPanel(self.settings)

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return ImageMetadataFileIngestModuleWithUI(self.settings)
    
    #=========================== end of Panel GUI basic configuration methods ===============================#
    


#============================================================================================================#
#                               -- MODULE'S MAIN FUNCTIONALITY RELATED CLASS --                              #
#============================================================================================================#

# File-level ingest module.  One gets created per thread.
# Looks at the attributes of the passed in file.
class ImageMetadataFileIngestModuleWithUI(FileIngestModule):

    _logger = Logger.getLogger(ImageMetadataFileIngestModuleWithUIFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Autopsy will pass in the settings from the UI panel
    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    # Where any setup and configuration is done
    # Add any setup code that you need here.
    def startUp(self, context):
        self.filesAnalyzed = 0
        
        # We start the logs that gives us information about if a box of the GUI has been set or not
        ImageAnalyzerLib.startUpLogs(self)

        pass

    # Where the analysis is done. Each file will be passed into here.
    # Add your analysis code in here.
    def process(self, file):
        
       # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK
        
         
        # At the moment we will only analyze 5 different type of files:
            # - JPG (JPEG)
            # - PNG (does not support EXIF metadata)
            # - TIFF
            # - GIF (does not support IPTC metadata)
            # - HEIC (supports EXIF and XMP, but IPTC ??)
        # If the file corresponds with one of the 5 types and the box is selected to analyze that specific file, we start the analysis
        if (
            (file.getName().lower().endswith(".jpg") and self.local_settings.getSetting("jpg") == "true") or
            (file.getName().lower().endswith(".png") and self.local_settings.getSetting("png") == "true") or
            (file.getName().lower().endswith(".tiff") and self.local_settings.getSetting("tiff") == "true") or
            (file.getName().lower().endswith(".gif") and self.local_settings.getSetting("gif") == "true") or
            (file.getName().lower().endswith(".heic") and self.local_settings.getSetting("heic") == "true")
            ):
            
            self.log(Level.INFO, "Found an image file with path: " + file.getLocalAbsPath())
            #self.log(Level.INFO, "Found a JPG file with path: " + file.getUniquePath())
             
            self.log(Level.INFO, "Platform used: " + PlatformUtil.getOSName())
            
            
            # Check the platform the user is using
            if "Mac" in PlatformUtil.getOSName():
                PATH = PATH_MACOS
                
                # Metadata Error Test
                #PATH = PATH_WINDOWS
                
            elif "Windows" in PlatformUtil.getOSName():
                PATH = PATH_WINDOWS
                    
                
            # Analyze the image metadata
            # If there is an error while analyzing the metadata, we will not run the module
            try:
                
                with ExifTool(PATH) as et:  
                    # metadata is a dictionary (key:value pair) 
                    # key => metadata type (tag)
                    # value => metadata value (value of the tag)
                    metadata = et.get_metadata(file.getLocalAbsPath())
                    
                    #metadata = et.get_metadata(file.getUniquePath())
                    
            except:
                
                ImageAnalyzerLib.postInformationForTheUser(self, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                           Level.SEVERE, IngestMessage.MessageType.ERROR, 
                                                           "Error reading metadata of current file " + file.getName())

                return IngestModule.ProcessResult.ERROR
                
            
            # A list with the tags of all the metadata found in the image
            imageMetadataTagList = list(metadata)
            
            # A list with the values of all the metadata found in the image
            imageMetadataValueList = list(metadata.values())
            
            
            self.filesAnalyzed += 1
            
            self.log(Level.INFO, "Files analyzed: " + str(self.filesAnalyzed))
            
            
            #=============================== start of IMAGE METADATA ANALYSIS ===============================#
            
            # Use blackboard class to index blackboard artifacts for keyword search
            blackboard = Case.getCurrentCase().getServices().getBlackboard()
            
            # If the Filter Mode checkbox is selected we will not add the analyzed images with its metadata in the artifact we have in the blackboard
            # Because if we only wanted to execute filters, we would have repited images (in the Image Metadata Analyzer artifact) every time we execute the module
            if (not self.local_settings.getSetting("filter") == "true"):
            
                # Creating a custom Artifact
                artId = blackboard.getOrAddArtifactType("TSK_IMAGE_METADATA", "Image Metadata Analyzer") #Blackboard Artifact Type
                artifact = file.newArtifact(artId.getTypeID())
                
                
                for m in range(0, len(metadata)):
                    
                    # Check the GUI box "EXIF"
                    if (self.local_settings.getSetting("exif") == "true") and (imageMetadataTagList[m].startswith("EXIF")):
                        
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct printing
                        # metadataValue is the str of each metadata value    
                        metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                        
                        # Add Attribute to the Artifact
                        try:
                            
                            ImageAnalyzerLib.addNewMetadataAttribute(blackboard, artifact, artId, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                     imageMetadataTagList[m], metadataValue)
                        except:
                            
                            ImageAnalyzerLib.postInformationForTheUser(self, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                       Level.WARNING, IngestMessage.MessageType.ERROR, 
                                                                       "Error adding EXIF Attribute " + imageMetadataTagList[m] + " to the Artifact!")
                                
                    # Check the GUI box "IPTC"
                    if (self.local_settings.getSetting("iptc") == "true") and (imageMetadataTagList[m].startswith("IPTC")):
                        
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct printing 
                        # metadataValue is the str of each metadata value    
                        metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                        
                         # Add Attribute to the Artifact
                        try:
                            
                            ImageAnalyzerLib.addNewMetadataAttribute(blackboard, artifact, artId, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                     imageMetadataTagList[m], metadataValue)
                        except:
                            
                            ImageAnalyzerLib.postInformationForTheUser(self, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                       Level.WARNING, IngestMessage.MessageType.ERROR, 
                                                                       "Error adding IPTC Attribute " + imageMetadataTagList[m] + " to the Artifact!")
                                          
                    # Check the GUI box "XMP"
                    if (self.local_settings.getSetting("xmp") == "true") and (imageMetadataTagList[m].startswith("XMP")):
                       
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct printing 
                        # metadataValue is the str of each metadata value    
                        metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                        
                         # Add Attribute to the Artifact
                        try:
                            
                            ImageAnalyzerLib.addNewMetadataAttribute(blackboard, artifact, artId, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                     imageMetadataTagList[m], metadataValue)
                        except:
                            
                            ImageAnalyzerLib.postInformationForTheUser(self, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                       Level.WARNING, IngestMessage.MessageType.ERROR, 
                                                                       "Error adding XMP Attribute " + imageMetadataTagList[m] + " to the Artifact!")
                            
                    # Add other metadata information found such as "File:", "Composite:", etc.
                    if self.local_settings.getSetting("other") == "true" and not (imageMetadataTagList[m].startswith("EXIF") or
                                                                                  imageMetadataTagList[m].startswith("IPTC") or
                                                                                  imageMetadataTagList[m].startswith("XMP")):
                      
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct printing
                        # metadataValue is the str of each metadata value    
                        metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                        
                        # Add Attribute to the Artifact
                        try:
                            
                            ImageAnalyzerLib.addNewMetadataAttribute(blackboard, artifact, artId, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                     imageMetadataTagList[m], metadataValue)
                        except:
                            
                            ImageAnalyzerLib.postInformationForTheUser(self, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                       Level.WARNING, IngestMessage.MessageType.ERROR, 
                                                                       "Error adding Other Attribute " + imageMetadataTagList[m] + " to the Artifact!")
                        
                
            #================================ end of IMAGE METADATA ANALYSIS ================================#
            
            
            #============================== start of IMAGE METADATA FILTERING ===============================#
            
            # Different levels:
            #   - 1st level => basic one condition filter
            #   - 2nd level => "AND" filter ("" + AND + "")
            #   - 3rd level => "OR" filter ("" + OR + "")
            #   - 4th level => "NOT" filter (NOT + "")
            #   - 5th level => filter by specific metadata attribute (Author == Jordi)
            #   - 6th level => filter by specific metadata attribute (Author != Jordi)
            #   - 7th level => filter by specific metadata attribute (Author CONTAIN Jordi)
            #   - 8th level => filter by specific metadata attribute (Author DOES NOT CONTAIN Jordi)
            # TODO: - 9th level => "AND", "OR", "NOT" mixed filter
            
            validation = 0
            
            pattern_1 = "[a-zA-Z0-9]"

            pattern_2 = "[a-zA-Z0-9]\s(AND)\s[a-zA-Z0-9]"
            
            pattern_3 = "[a-zA-Z0-9]\s(OR)\s[a-zA-Z0-9]"
            
            pattern_4 = "(NOT)\s[a-zA-Z0-9]"
            
            pattern_5 = "[a-zA-Z0-9]\s(==)\s[a-zA-Z0-9]"
            
            pattern_6 = "[a-zA-Z0-9]\s(!=)\s[a-zA-Z0-9]"
            
            pattern_7 = "[a-zA-Z0-9]\s(CONTAINS)\s[a-zA-Z0-9]"
            
            pattern_8 = "[a-zA-Z0-9]\s(DOES\sNOT\sCONTAIN)\s[a-zA-Z0-9]"
            
            self.filterFound = True
            #imageFound = False
            
            self.fileHitName_info = ""
            self.fileHitComment_info = ""
            
            global imageFound
            

            for m in range(filterCounter):
                self.wordToSearch = self.local_settings.getSetting("word_search_" + str(m+1))
                self.log(Level.INFO, "word_search_" + str(m+1) + ": " + self.wordToSearch)
                
            
            interestingFileHitArtifact = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            
            for m in range(filterCounter):
                
                self.wordToSearch = self.local_settings.getSetting("word_search_" + str(m+1))
                
                self.fileHitName_info += self.wordToSearch + " | \n"
                
                
                if self.filterFound is True:
                
                    # 5th LEVEL: "=="
                    if (re.search(pattern_5, self.wordToSearch)):
                        validation = 0
                        
                        # output[0] = tag of the metadata
                        # output[1] = corresponding value of the metadata
                        output = re.split("\s==\s", self.wordToSearch)
                        
                        for m in range(0, len(metadata)):
                            
                            metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                            
                            metadataTagPairs = re.split(":", imageMetadataTagList[m])
                
                            # There is usually an error with the first metadata because does not cotain the ':', 
                            # and for that reason there is only 1 name in the list and not 2
                            try:
                                metadataTag = metadataTagPairs[1]
                            except:
                                metadataTag = metadataTagPairs[0] 
                            
                            # If the tag is the same as introduced and it is the same name as the metadata value introduced, the filter is found
                            if metadataTag.lower() == output[0].lower() and metadataValue.lower() == output[1].lower():
                                validation += 1
                                metadataEntireTag = imageMetadataTagList[m]
                                break
                        
                        # If it is true, the "==" condition has been accomplished
                        if validation == 1:
        
                            metadataTagValue = metadataEntireTag + "=>" + metadataValue 
                            
                            self.fileHitComment_info += "\n" + metadataTagValue + " | "
                            
                        else:
                            self.filterFound = False
                            self.log(Level.INFO, '"' + self.wordToSearch + '" filter not found in the metadata of ' + '"' + file.getName() + '"')
                        
                    # 6th LEVEL: "!="
                    elif (re.search(pattern_6, self.wordToSearch)):
                        validation = 0
                        
                        # output[0] = tag of the metadata
                        # output[1] = corresponding value of the metadata
                        output = re.split("\s!=\s", self.wordToSearch)
                        
                        for m in range(0, len(metadata)):
                            
                            metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                            
                            metadataTagPairs = re.split(":", imageMetadataTagList[m])
                
                            # There is usually an error with the first metadata because does not cotain the ':', 
                            # and for that reason there is only 1 name in the list and not 2
                            try:
                                metadataTag = metadataTagPairs[1]
                            except:
                                metadataTag = metadataTagPairs[0] 
                            
                            # If the tag is the same as introduced and it is NOT the same name as the metadata value introduced, the filter is found
                            if metadataTag.lower() == output[0].lower() and metadataValue.lower() != output[1].lower():
                                validation += 1
                                metadataEntireTag = imageMetadataTagList[m]
                                break
                        
                        # If it is true, the "!=" condition has been accomplished
                        if validation == 1:
                            
                            metadataTagValue = metadataEntireTag + "=>" + metadataValue 
                            
                            self.fileHitComment_info += "\n" + metadataTagValue + " | "
                            
                        else:
                            self.filterFound = False
                            self.log(Level.INFO, '"' + self.wordToSearch + '" filter not found in the metadata of ' + '"' + file.getName() + '"')
               
                    # 7th LEVEL: "CONTAINS"
                    elif (re.search(pattern_7, self.wordToSearch)):
                        validation = 0
                        
                        # output[0] = tag of the metadata
                        # output[1] = corresponding value of the metadata
                        output = re.split("\sCONTAINS\s", self.wordToSearch)
                        
                        for m in range(0, len(metadata)):
                            
                            metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                            
                            metadataTagPairs = re.split(":", imageMetadataTagList[m])
                
                            # There is usually an error with the first metadata because does not cotain the ':', 
                            # and for that reason there is only 1 name in the list and not 2
                            try:
                                metadataTag = metadataTagPairs[1]
                            except:
                                metadataTag = metadataTagPairs[0] 
                            
                            # If the tag is the same as introduced and it CONTAINS the metadata value introduced, the filter is found
                            # Here is the difference between '==' and 'CONTAINS' => output[1] in metadataValue
                            if (metadataTag.lower() == output[0].lower()) and (output[1].lower() in metadataValue.lower()):
                                validation += 1
                                metadataEntireTag = imageMetadataTagList[m]
                                break
                        
                        # If it is true, the "CONTAINS" condition has been accomplished
                        if validation == 1:
                            
                            metadataTagValue = metadataEntireTag + "=>" + metadataValue 
                            
                            self.fileHitComment_info += "\n" + metadataTagValue + " | "

                        else:
                            self.filterFound = False
                            self.log(Level.INFO, '"' + self.wordToSearch + '" filter not found in the metadata of ' + '"' + file.getName() + '"')
                    
                    # 8th LEVEL: "DOES NOT CONTAIN"
                    elif (re.search(pattern_8, self.wordToSearch)):
                        validation = 0
                        
                        # output[0] = tag of the metadata
                        # output[1] = corresponding value of the metadata
                        output = re.split("\sDOES\sNOT\sCONTAIN\s", self.wordToSearch)
                        
                        for m in range(0, len(metadata)):
                            
                            metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                            
                            metadataTagPairs = re.split(":", imageMetadataTagList[m])
                
                            # There is usually an error with the first metadata because does not cotain the ':', 
                            # and for that reason there is only 1 name in the list and not 2
                            try:
                                metadataTag = metadataTagPairs[1]
                            except:
                                metadataTag = metadataTagPairs[0] 
                            
                            # If the tag is the same as introduced and it DOES NOT CONTAIN the metadata value introduced, the filter is found
                            # Here is the difference between '!=' and 'DOES NOT CONTAIN' => output[1] not in metadataValue
                            if (metadataTag.lower() == output[0].lower()) and (output[1].lower() not in metadataValue.lower()):
                                validation += 1
                                metadataEntireTag = imageMetadataTagList[m]
                                break
                        
                        # If it is true, the "DOES NOT CONTAIN" condition has been accomplished
                        if validation == 1:
                            
                            metadataTagValue = metadataEntireTag + "=>" + metadataValue 
                            
                            self.fileHitComment_info += "\n" + metadataTagValue + " | "
 
                        else:
                            self.filterFound = False
                            self.log(Level.INFO, '"' + self.wordToSearch + '" filter not found in the metadata of ' + '"' + file.getName() + '"')
                    
                    # 2nd LEVEL: "AND". 
                    #   - We can include as many "AND" as we want: Canon AND iPhone AND Jordi AND ...    
                    elif (re.search(pattern_2, self.wordToSearch)):
                        metadataTagValueList = []
                        validation = 0
                        output = re.split("\sAND\s", self.wordToSearch) # Output is a list containing the words to search
                        
                        for x in output:
                            
                            for m in range(0, len(metadata)):
                                
                                # Check the value of the metadata: if it is not a string, convert it to string for a correct evaluation 
                                # metadataValue is the str of each metadata value                   
                                metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                                    
                                if x.lower() in metadataValue.lower():
                                    validation += 1
                                    break
                        
                        # If it is true, the "AND" condition has been accomplished        
                        if validation == len(output):
                            
                            # Adding the comments, that is the tags where the metadata values have been found
                            for x in output:
                                for m in range(0, len(metadata)):
                                    
                                    metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                                    
                                    if x.lower() in metadataValue.lower():
                                        metadataTagValue = imageMetadataTagList[m] + "=>" + metadataValue
                                        metadataTagValueList.append(metadataTagValue)
                            
                            self.fileHitComment_info += "\n" + ' | \n'.join(metadataTagValueList)
                            
                        else:
                            self.filterFound = False
                            self.log(Level.INFO, '"' + self.wordToSearch + '" filter not found in the metadata of ' + '"' + file.getName() + '"')
                            
                    # 3rd LEVEL: "OR". 
                    #   - We can include as many "OR" as we want: Canon OR iPhone OR Jordi OR ...
                    elif (re.search(pattern_3, self.wordToSearch)):
                        metadataTagValueList = []
                        validation = 0
                        output = re.split("\sOR\s", self.wordToSearch) # Output is a list containing the words to search
                        
                        for x in output:
                            
                            for m in range(0, len(metadata)):
                                
                                # Check the value of the metadata: if it is not a string, convert it to string for a correct evaluation 
                                # metadataValue is the str of each metadata value                   
                                metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                                               
                                if x.lower() in metadataValue.lower():
                                    validation += 1
                        
                        # If it is true, the "OR" condition has been accomplished
                        if validation > 0:
                            
                            # Adding the comments, that is the tags where the metadata values have been found
                            for x in output:
                                for m in range(0, len(metadata)):
                                    
                                    metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                                    
                                    if x.lower() in metadataValue.lower():
                                        metadataTagValue = imageMetadataTagList[m] + "=>" + metadataValue
                                        metadataTagValueList.append(metadataTagValue)
                                        
                            self.fileHitComment_info += "\n" + ' | \n'.join(metadataTagValueList)
                            
                        else:
                            self.filterFound = False
                            self.log(Level.INFO, '"' + self.wordToSearch + '" filter not found in the metadata of ' + '"' + file.getName() + '"')
                                          
                    # 4th LEVEL: "NOT". 
                    #   - We can only include one "not"
                    elif (re.search(pattern_4, self.wordToSearch)):
                        validation = 0
                        output = re.sub("NOT\s", "", self.wordToSearch) # Output is a list containing the words to search
                            
                        for m in range(0, len(metadata)):
                            
                            # Check the value of the metadata: if it is not a string, convert it to string for a correct evaluation 
                            # metadataValue is the str of each metadata value                   
                            metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                                           
                            if output.lower() in metadataValue.lower():
                                validation += 1
                        
                        # If it is true, the "NOT" condition has been accomplished
                        if validation == 0:
                            
                            self.fileHitComment_info += "\n" + "The metadata of the image does NOT contain the word searched: " + output + " | "
                            
                        else:
                            self.filterFound = False
                            self.log(Level.INFO, '"' + self.wordToSearch + '" filter not found in the metadata of ' + '"' + file.getName() + '"')
                            
                    # 1st LEVEL: One word. 
                    #   - We can only include one word to search
                    elif (re.search(pattern_1, self.wordToSearch)):
                        validation = 0
                        metadataTagValueList = []
                        output = self.wordToSearch
                            
                        for m in range(0, len(metadata)):
                            
                            # Check the value of the metadata: if it is not a string, convert it to string for a correct evaluation 
                            # metadataValue is the str of each metadata value                   
                            metadataValue = ImageAnalyzerLib.metadataToString(imageMetadataValueList[m])
                                           
                            if output.lower() in metadataValue.lower():
                                metadataTagValue = imageMetadataTagList[m] + "=>" + metadataValue
                                metadataTagValueList.append(metadataTagValue)
                                validation += 1
                        
                        # If it is true, the 1st level condition has been accomplished
                        # Adding the comments, that is the tags where the metadata values have been found
                        if validation > 0:
                            
                            self.fileHitComment_info += "\n" + ' | \n'.join(metadataTagValueList)
                            
                        else:
                            self.filterFound = False
                            self.log(Level.INFO, '"' + self.wordToSearch + '" filter not found in the metadata of ' + '"' + file.getName() + '"')
                            
                    elif (self.wordToSearch == ""):
                        
                        self.filterFound = False
                        self.log(Level.INFO, "You have not entered any filter")
                                   
                    else:
                        
                        self.filterFound = False
                        ImageAnalyzerLib.postInformationForTheUser(self, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                   Level.WARNING, IngestMessage.MessageType.ERROR, "Incorrect filter's input!")
                            
            # If we find an image that contains the filters, we add the Interesting File Hit Attribute            
            if self.filterFound:
                
                # Dictionary (key:value) with the attribute name (key) and its type (value)
                # { AttributeName: AttributeType }
                attributesDict = {
                    self.fileHitName_info: BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                    self.fileHitComment_info: BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT
                    }
                
                ImageAnalyzerLib.addInterestingFileHitAttributes(interestingFileHitArtifact,
                                                                    ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                    attributesDict)
                
                imageFound = True
                

            self.log(Level.INFO, "Image Found: " + str(imageFound))
            
            #============================== end of IMAGE METADATA FILTERING ==============================#
            
            
        return IngestModule.ProcessResult.OK
    
    

    # Where any shutdown code is run and resources are freed.
    def shutDown(self):
        # As a final part, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.INFO, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                str(self.filesAnalyzed) + " files analyzed")
        ingestServices = IngestServices.getInstance().postMessage(message)
        
        global imageFound
        
        # If we have not found any image that contain the filters introduced, we send a message to the user
        if (not imageFound) and (self.fileHitName_info != " | \n"):
            self.log(Level.WARNING, 'Filter "'  + self.fileHitName_info + '" NOT FOUND !')
            ImageAnalyzerLib.postInformationForTheUser(self, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                       Level.WARNING, IngestMessage.MessageType.WARNING, 'Filter "'  + self.fileHitName_info + '" NOT FOUND !')
    
        
        


#==============================================================================#
#                        -- PANEL GUI RELATED CLASSES --                       #
#==============================================================================#

#========================= start of GENERIC GUI CLASS =========================#

# UI that is shown to user for each ingest job so they can configure the job.
class ImageMetadataFileIngestModuleWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'

    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        #self.customizeComponents()
            

    def initComponents(self):
        
        self.setLayout(None)
        
        self.card = CardLayout()
        self.mainPanel = JPanel(self.card)
        self.mainPanel.setBounds(0,0,350,265) 
        
        metadataAnalyzerGUI = JMetadataAnalyzerGUI(self.local_settings, self)
        metadataFilterGUI = JMetadataFilterGUI(self.local_settings, self)
        
        metadataAnalyzerGUIPanel = metadataAnalyzerGUI.getPanel()
        metadataFilterGUIPanel = metadataFilterGUI.getPanel()
        
        self.mainPanel.add(metadataAnalyzerGUIPanel, "1")
        self.mainPanel.add(metadataFilterGUIPanel, "2")
        
        self.add(self.mainPanel)
        
        button1 = JButton("Analyzer Menu", actionPerformed = self.testEvent1)
        button1.setHorizontalAlignment(SwingConstants.CENTER)
        button1.setBounds(15, 275, 125, 22)
        self.add(button1)
        
        button2 = JButton("Filter Menu", actionPerformed = self.testEvent2)
        button2.setHorizontalAlignment(SwingConstants.CENTER)
        button2.setBounds(160, 275, 125, 22)
        self.add(button2)
        
        button3 = JButton("Load Module", actionPerformed = metadataFilterGUI.wordCheckBoxEvent)
        button3.setHorizontalAlignment(SwingConstants.CENTER)
        button3.setBounds(0, 300, 300, 22)
        self.add(button3)
        
        self.module_label = JLabel("Module NOT loaded yet!")
        self.module_label.setForeground(Color.red)
        self.module_label.setHorizontalAlignment(SwingConstants.CENTER)
        self.module_label.setFont(Font("Default", Font.BOLD, 11))
        self.module_label.setBounds(0, 325, 300, 20)
        self.add(self.module_label)
        
        
    def customizeComponents(self):
        pass
    
    
    def testEvent1(self, event):
        self.card.show(self.mainPanel, "1")
        
        
    def testEvent2(self, event):
        self.card.show(self.mainPanel, "2")
        
    def getModuleLabel(self):
        return self.module_label

    # Return the settings used
    def getSettings(self):
        return self.local_settings

#========================== end of GENERIC GUI CLASS ==========================#    


#==================== start of METADATA ANALYZER GUI CLASS ====================#
    
class JMetadataAnalyzerGUI:
    
    def __init__(self, settings, frame):
        
        self.local_settings = settings
        self.frame = frame
        self.initComponents()
        self.customizeComponents()
        
        
    def initComponents(self):
        
        self.panel = JPanel()
        self.panel.setLayout(None)
        #self.panel.setBackground(Color.gray) 
        
        title1 = JLabel("IMAGE METADATA ANALYZER")
        title1.setHorizontalAlignment(SwingConstants.LEFT)
        title1.setFont(Font("Tahoma", Font.BOLD, 14))
        title1.setBounds(5, 10, 300, 20)
        self.panel.add(title1)
        
        label1 = JLabel("Select the type of Metadata you want to analyze:")
        label1.setHorizontalAlignment(SwingConstants.LEFT)
        label1.setFont(Font("Default", Font.PLAIN, 11))
        label1.setBounds(5, 40, 300, 20)
        self.panel.add(label1)
        
        # EXIF checkbox
        self.exif_checkbox = JCheckBox("EXIF Metadata", actionPerformed=self.exifCheckBoxEvent)
        self.exif_checkbox.setBounds(10, 60, 110, 20)
        self.panel.add(self.exif_checkbox)
        
        # IPTC checkbox
        self.iptc_checkbox = JCheckBox("IPTC Metadata", actionPerformed=self.iptcCheckBoxEvent)
        self.iptc_checkbox.setBounds(130, 60, 110, 20)
        self.panel.add(self.iptc_checkbox)
        
        # XMP checkbox
        self.xmp_checkbox = JCheckBox("XMP Metadata", actionPerformed=self.xmpCheckBoxEvent)
        self.xmp_checkbox.setBounds(10, 80, 110, 20)
        self.panel.add(self.xmp_checkbox)
        
        # Other checkbox
        self.other_checkbox = JCheckBox("Other", actionPerformed=self.otherCheckBoxEvent)
        self.other_checkbox.setBounds(130, 80, 110, 20)
        self.panel.add(self.other_checkbox)
        
        
        label2 = JLabel("Select the type of image file you want to analyze:")
        label2.setHorizontalAlignment(SwingConstants.LEFT)
        label2.setFont(Font("Default", Font.PLAIN, 11))
        label2.setBounds(5, 110, 300, 20)
        self.panel.add(label2)
        
        # JPG checkbox
        self.jpg_checkbox = JCheckBox("JPG (JPEG)", actionPerformed=self.jpgCheckBoxEvent)
        self.jpg_checkbox.setBounds(10, 130, 80, 20)
        self.panel.add(self.jpg_checkbox)
        
        # PNG checkbox
        self.png_checkbox = JCheckBox("PNG", actionPerformed=self.pngCheckBoxEvent)
        self.png_checkbox.setBounds(105, 130, 80, 20)
        self.panel.add(self.png_checkbox)
        
        # TIFF checkbox
        self.tiff_checkbox = JCheckBox("TIFF", actionPerformed=self.tiffCheckBoxEvent)
        self.tiff_checkbox.setBounds(200, 130, 80, 20)
        self.panel.add(self.tiff_checkbox)
        
        # GIF checkbox
        self.gif_checkbox = JCheckBox("GIF", actionPerformed=self.gifCheckBoxEvent)
        self.gif_checkbox.setBounds(10, 150, 80, 20)
        self.panel.add(self.gif_checkbox)
        
        # HEIC checkbox
        self.heic_checkbox = JCheckBox("HEIC", actionPerformed=self.heicCheckBoxEvent)
        self.heic_checkbox.setBounds(105, 150, 80, 20)
        self.panel.add(self.heic_checkbox)

        self.frame.add(self.panel)
        
        
    def customizeComponents(self):
        
        # Mantain the GUI EXIF box selected if selected before
        self.exif_checkbox.setSelected(self.local_settings.getSetting("exif") == "true")
        
        # Mantain the GUI IPTC box selected if selected before
        self.iptc_checkbox.setSelected(self.local_settings.getSetting("iptc") == "true")
        
        # Mantain the GUI XMP box selected if selected before
        self.xmp_checkbox.setSelected(self.local_settings.getSetting("xmp") == "true")
        
        # Mantain the GUI Other box selected if selected before
        self.other_checkbox.setSelected(self.local_settings.getSetting("other") == "true")
        
        # Mantain the GUI JPG box selected if selected before
        self.jpg_checkbox.setSelected(self.local_settings.getSetting("jpg") == "true")
        
        # Mantain the GUI PNG box selected if selected before
        self.png_checkbox.setSelected(self.local_settings.getSetting("png") == "true")
        
        # Mantain the GUI TIFF box selected if selected before
        self.tiff_checkbox.setSelected(self.local_settings.getSetting("tiff") == "true")
        
        # Mantain the GUI GIF box selected if selected before
        self.gif_checkbox.setSelected(self.local_settings.getSetting("gif") == "true")
        
        # Mantain the GUI HEIC box selected if selected before
        self.heic_checkbox.setSelected(self.local_settings.getSetting("heic") == "true")
        
        
    def exifCheckBoxEvent(self, event):
        if self.exif_checkbox.isSelected():
            self.local_settings.setSetting("exif", "true")
        else:
            self.local_settings.setSetting("exif", "false")
            
    
    def iptcCheckBoxEvent(self, event):
        if self.iptc_checkbox.isSelected():
            self.local_settings.setSetting("iptc", "true")
        else:
            self.local_settings.setSetting("iptc", "false")
            
    def xmpCheckBoxEvent(self, event):
        if self.xmp_checkbox.isSelected():
            self.local_settings.setSetting("xmp", "true")
        else:
            self.local_settings.setSetting("xmp", "false")
            
    def otherCheckBoxEvent(self, event):
        if self.other_checkbox.isSelected():
            self.local_settings.setSetting("other", "true")
        else:
            self.local_settings.setSetting("other", "false")
            
    def jpgCheckBoxEvent(self, event):
        if self.jpg_checkbox.isSelected():
            self.local_settings.setSetting("jpg", "true")
        else:
            self.local_settings.setSetting("jpg", "false")
            
    def pngCheckBoxEvent(self, event):
        if self.png_checkbox.isSelected():
            self.local_settings.setSetting("png", "true")
        else:
            self.local_settings.setSetting("png", "false")
            
    def tiffCheckBoxEvent(self, event):
        if self.tiff_checkbox.isSelected():
            self.local_settings.setSetting("tiff", "true")
        else:
            self.local_settings.setSetting("tiff", "false")
            
    def gifCheckBoxEvent(self, event):
        if self.gif_checkbox.isSelected():
            self.local_settings.setSetting("gif", "true")
        else:
            self.local_settings.setSetting("gif", "false")
            
    def heicCheckBoxEvent(self, event):
        if self.heic_checkbox.isSelected():
            self.local_settings.setSetting("heic", "true")
        else:
            self.local_settings.setSetting("heic", "false")
            
    def getPanel(self):
        return self.panel
            
#===================== end of METADATA ANALYZER GUI CLASS =====================#      
            
#===================== start of METADATA FILTER GUI CLASS =====================#

class JMetadataFilterGUI:
    
    word_search_list = []
    
    def __init__(self, settings, frame):
        
        self.local_settings = settings
        
        self.frame = frame
        self.initComponents()
        self.customizeComponents()
        
        
    
    def initComponents(self):
        
        global filterCounter
        
        self.panel = JPanel()
        self.panel.setLayout(None)
        #self.panel.setBackground(Color.yellow)
        self.panel.setAlignmentX(Component.LEFT_ALIGNMENT)
        
        filterCounter += 1
        self.lastPosition = 120
    
        title2 = JLabel("IMAGE METADATA FILTER")
        title2.setHorizontalAlignment(SwingConstants.LEFT)
        title2.setFont(Font("Tahoma", Font.BOLD, 14))
        title2.setBounds(5, 10, 250, 20)
        self.panel.add(title2)
        
        button1 = JButton("+", actionPerformed=self.addEvent)
        button1.setHorizontalAlignment(SwingConstants.CENTER)
        button1.setBounds(230, 10, 43, 22)
        self.panel.add(button1)
        
        self.advertisment = JLabel("You have added " + str(filterCounter) + " filters")
        self.advertisment.setForeground(Color.green)
        self.advertisment.setHorizontalAlignment(SwingConstants.CENTER)
        self.advertisment.setFont(Font("Default", Font.ITALIC, 10))
        self.advertisment.setBounds(5, 33, 250, 20)
        self.panel.add(self.advertisment)
        
        self.filter_checkbox = JCheckBox("Use only the Image Metadata Filter", actionPerformed=self.filterChekBoxEvent)
        self.filter_checkbox.setBounds(5, 55, 300, 20)
        self.panel.add(self.filter_checkbox)
        
        
        label3 = JLabel("Write the filters you want to introduce and search it:")
        label3.setHorizontalAlignment(SwingConstants.LEFT)
        label3.setFont(Font("Default", Font.PLAIN, 12))
        label3.setBounds(5, 80, 300, 20)
        self.panel.add(label3)
        
        
        label3_1 = JLabel("For example: Name1 OR Name2")
        label3_1.setHorizontalAlignment(SwingConstants.LEFT)
        label3_1.setFont(Font("Default", Font.ITALIC, 8))
        label3_1.setBounds(5, 95, 300, 20)
        self.panel.add(label3_1)
        
        
        self.lbl_1 = JLabel("Filter 1: ")
        self.lbl_1.setBounds(10, 120, 50, 20)
        self.lbl_1.setFont(Font("Default", Font.ITALIC, 11))
        self.panel.add(self.lbl_1)
        
        self.word_search = JTextField()
        self.word_search.setBounds(65, 120, 200, 23)
        self.panel.add(self.word_search)
        
        # Creation of a list to access to all JTextFields of each filter
        # the position of the list corresponds to the number of the filter - 1
        self.word_search_list = [self.word_search]
        
        
        self.panel.setPreferredSize(Dimension(300,650))
        self.scroll = JScrollPane(self.panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        self.scroll.setPreferredSize(Dimension(300,650))
        
        #frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE)
        self.frame.add(self.scroll)
        self.frame.setVisible(True)

    
    def customizeComponents(self):
        # Mantain the GUI "Use only the Image Metadata Filter" box selected if selected before
        #self.filter_checkbox.setSelected(self.local_settings.getSetting("filter") == "true")
        pass
        
    def addEvent(self, event):
        self.addNewFilter()
        
    def wordCheckBoxEvent(self, event):
        self.module_label = ImageMetadataFileIngestModuleWithUISettingsPanel.getModuleLabel()
        self.module_label.text = "Module loaded correctly!"
        self.module_label.setForegorund(Color.green)
        
        for m in range(len(self.word_search_list)):
            self.local_settings.setSetting("word_search_" + str(m + 1), self.word_search_list[m].getText())
        
    def filterChekBoxEvent(self, event):
        if self.filter_checkbox.isSelected():
            self.local_settings.setSetting("filter", "true")
        else:
            self.local_settings.setSetting("filter", "false")
        
    def addNewFilter(self):
        
        global filterCounter
        
        filterCounter += 1
        self.lastPosition += 25
        
        if (filterCounter <= 20):
            self.lbl_2 = JLabel("Filter " + str(filterCounter) + ":")
            self.lbl_2.setBounds(10, self.lastPosition, 50, 20)
            self.lbl_2.setFont(Font("Default", Font.ITALIC, 11))
            self.panel.add(self.lbl_2)
            
            self.word_search_2 = JTextField()
            self.word_search_2.setBounds(65, self.lastPosition, 200, 23)
            self.panel.add(self.word_search_2)
            
            self.word_search_list.append(self.word_search_2)
            
            self.advertisment.text = "You have added " + str(filterCounter) + " filters"
            
        else:
            self.advertisment.setForeground(Color.red)
            self.advertisment.text = "You have added the maximum number of filters!"
        
        # Refresh the panel, with this we don't have problems when adding new filters
        # We click the button to add a new filter and the filter appears immediately
        self.panel.revalidate();
        self.panel.repaint();
        

    def getPanel(self):
        return self.scroll
    
    
#====================== end of METADATA FILTER GUI CLASS ======================#
    
            
            
        
        
        
        
    
    
    