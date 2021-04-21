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
from java.awt import Panel, BorderLayout, EventQueue, GridLayout, GridBagLayout, GridBagConstraints, Font, Color 
from javax.swing import JCheckBox, JLabel, JTextField, JButton, JFrame, JComboBox, JProgressBar, JMenuBar, JMenuItem, JTabbedPane, JPasswordField, SwingConstants, BoxLayout, JPanel
from javax.swing.border import TitledBorder, EtchedBorder, EmptyBorder
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
import re

PATH_WINDOWS = "C:\WINDOWS\exiftool.exe" #WINDOWS path to the exiftool executable
PATH_MACOS = "/usr/local/bin/exiftool" #MACOS path to the exiftool executable

# TODO: Rename this to something more specific
class ImageMetadataFileIngestModuleWithUIFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Image Metadata Analyzer with GUI"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Autopsy module for automated analysis of image metadata."

    def getModuleVersionNumber(self):
        return "1.0"

    # TODO: Update class name to one that you create below
    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()
    
    
    #====================== PANEL GUI ==========================#
    
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
    
    #===========================================================#
    


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
        
        # Determine if user configured exif in UI
        if self.local_settings.getSetting("exif") == "true":
            self.log(Level.INFO, "exif is set")
        else:
            self.log(Level.INFO, "exif is not set")
            
        # Determine if user configured iptc in UI
        if self.local_settings.getSetting("iptc") == "true":
            self.log(Level.INFO, "iptc is set")
        else:
            self.log(Level.INFO, "iptc is not set")
            
        # Determine if user configured xmp in UI
        if self.local_settings.getSetting("xmp") == "true":
            self.log(Level.INFO, "xmp is set")
        else:
            self.log(Level.INFO, "xmp is not set")
            
        # Determine if user configured other in UI
        if self.local_settings.getSetting("other") == "true":
            self.log(Level.INFO, "other is set")
        else:
            self.log(Level.INFO, "other is not set")
            
        # Determine if user configured jpg in UI
        if self.local_settings.getSetting("jpg") == "true":
            self.log(Level.INFO, "jpg is set")
        else:
            self.log(Level.INFO, "jpg is not set")
            
        # Determine if user configured png in UI
        if self.local_settings.getSetting("png") == "true":
            self.log(Level.INFO, "png is set")
        else:
            self.log(Level.INFO, "png is not set")
            
        # Determine if user configured tiff in UI
        if self.local_settings.getSetting("tiff") == "true":
            self.log(Level.INFO, "tiff is set")
        else:
            self.log(Level.INFO, "tiff is not set")
            
        # Determine if user configured gif in UI
        if self.local_settings.getSetting("gif") == "true":
            self.log(Level.INFO, "gif is set")
        else:
            self.log(Level.INFO, "gif is not set")
            
        # Determine if user configured heic in UI
        if self.local_settings.getSetting("heic") == "true":
            self.log(Level.INFO, "heic is set")
        else:
            self.log(Level.INFO, "heic is not set")


        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # Add your analysis code in here.
    def process(self, file):
       # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK
        
        #progressBar.switchToIndeterminate()
        
         
        # At the moment we will only analyze 5 different type of files:
            # - JPG (JPEG)
            # - PNG (does not support EXIF metadata)
            # - TIFF
            # - GIF (does not support IPTC metadata)
            # - HEIC (supports EXIF and XMP, but IPTC ??)
        if (
            (file.getName().lower().endswith(".jpg") and self.local_settings.getSetting("jpg") == "true") or
            (file.getName().lower().endswith(".png") and self.local_settings.getSetting("png") == "true") or
            (file.getName().lower().endswith(".tiff") and self.local_settings.getSetting("tiff") == "true") or
            (file.getName().lower().endswith(".gif") and self.local_settings.getSetting("gif") == "true") or
            (file.getName().lower().endswith(".heic") and self.local_settings.getSetting("heic") == "true")
            ):
            
            self.log(Level.INFO, "Found a image file with path: " + file.getLocalAbsPath())
            #self.log(Level.INFO, "Found a JPG file with path: " + file.getUniquePath())
            self.filesAnalyzed += 1
            self.log(Level.INFO, "Files analyzed: " + str(self.filesAnalyzed))
            #progressBar.progress("Analyzing " + file.getName())
            
            #if self.local_settings.getSetting("exif") == "true":
             #   self.filesAnalyzed += 1
             
            self.log(Level.INFO, "Platform used: " + PlatformUtil.getOSName())
            
            self.log(Level.INFO, "Word searched: " + self.local_settings.getSetting("word_search"))
            
            # Check the platform the user is using
            if "Mac" in PlatformUtil.getOSName():
                PATH = PATH_MACOS
                
            elif "Windows" in PlatformUtil.getOSName():
                PATH = PATH_WINDOWS
                    
                
            # Analyze the image metadata
            try:
                with ExifTool(PATH) as et:   
                    metadata = et.get_metadata(file.getLocalAbsPath())
                    #metadata = et.get_metadata(file.getUniquePath())
            except:
                self.log(Level.WARNING, "Error reading metadata of current file " + file.getName())
    
            
            # Use blackboard class to index blackboard artifacts for keyword search
            blackboard = Case.getCurrentCase().getServices().getBlackboard()
            
            
            
            #============================== start of IMAGE METADATA ANALYSIS ==============================#
            
            # If the Filter Mode checkbox is selected we will not add the analyzed images with its metadata in the artifact we have in the blackboard
            # Because if we only wanted to execute filters, we would have repited images (in the Image Metadata Analyzer artifact) every time we execute the module
            if (self.local_settings.getSetting("filter") == "false"):
            
                # Creating a custom Artifact
                artId = blackboard.getOrAddArtifactType("TSK_IMAGE_METADATA", "Image Metadata Analyzer") #Blackboard Artifact Type
                artifact = file.newArtifact(artId.getTypeID())
                
                
                for m in range(0, len(metadata)):
                    
                    # Check the GUI box "EXIF"
                    if (self.local_settings.getSetting("exif") == "true") and (list(metadata)[m].startswith("EXIF")):
                        
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct printing                    
                        if type((list(metadata.values())[m])) is not str:
                            metadata_att = str(list(metadata.values())[m])
                        else:
                            metadata_att = list(metadata.values())[m]
                        
                        # Add the new Attribute with the value of the metadata analyzed
                        attId = blackboard.getOrAddAttributeType("TSK_" + list(metadata)[m], BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, list(metadata)[m])
                        attribute = BlackboardAttribute(attId, ImageMetadataFileIngestModuleWithUIFactory.moduleName, metadata_att)
                        
                        # Adding the Attribute to the Artifact
                        try:  
                            artifact.addAttribute(attribute)
                        except:
                            self.log(Level.WARNING, "Error adding EXIF Attribute" + list(metadata)[m] + "to the Artifact!")
                            
                    
                            
                    # Check the GUI box "IPTC"
                    if (self.local_settings.getSetting("iptc") == "true") and (list(metadata)[m].startswith("IPTC")):
                        
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct printing                    
                        if type((list(metadata.values())[m])) is not str:
                            metadata_att = str(list(metadata.values())[m])
                        else:
                            metadata_att = list(metadata.values())[m]
                        
                        # Add the new Attribute with the value of the metadata analyzed
                        attId = blackboard.getOrAddAttributeType("TSK_" + list(metadata)[m], BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, list(metadata)[m])
                        attribute = BlackboardAttribute(attId, ImageMetadataFileIngestModuleWithUIFactory.moduleName, metadata_att)
                        
                        # Adding the Attribute to the Artifact
                        try:  
                            artifact.addAttribute(attribute)
                        except:
                            self.log(Level.WARNING, "Error adding IPTC Attribute" + list(metadata)[m] + "to the Artifact!")
                            
                            
                    # Check the GUI box "XMP"
                    if (self.local_settings.getSetting("xmp") == "true") and (list(metadata)[m].startswith("XMP")):
                        
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct printing                    
                        if type((list(metadata.values())[m])) is not str:
                            metadata_att = str(list(metadata.values())[m])
                        else:
                            metadata_att = list(metadata.values())[m]
                        
                        # Add the new Attribute with the value of the metadata analyzed
                        attId = blackboard.getOrAddAttributeType("TSK_" + list(metadata)[m], BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, list(metadata)[m])
                        attribute = BlackboardAttribute(attId, ImageMetadataFileIngestModuleWithUIFactory.moduleName, metadata_att)
                        
                        # Adding the Attribute to the Artifact
                        try:  
                            artifact.addAttribute(attribute)
                        except:
                            self.log(Level.WARNING, "Error adding XMP Attribute" + list(metadata)[m] + "to the Artifact!")
                    
                    # Add other metadata information found such as "File:", "Composite:", etc.
                    if self.local_settings.getSetting("other") == "true" and not (list(metadata)[m].startswith("EXIF") or
                                                                                  list(metadata)[m].startswith("IPTC") or
                                                                                  list(metadata)[m].startswith("XMP")):
                        
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct printing                    
                        if type((list(metadata.values())[m])) is not str:
                            metadata_att = str(list(metadata.values())[m])
                        else:
                            metadata_att = list(metadata.values())[m]
                        
                        # Add the new Attribute with the value of the metadata analyzed
                        attId = blackboard.getOrAddAttributeType("TSK_" + list(metadata)[m], BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, list(metadata)[m])
                        attribute = BlackboardAttribute(attId, ImageMetadataFileIngestModuleWithUIFactory.moduleName, metadata_att)
                        
                        # Adding the Attribute to the Artifact
                        try:  
                            artifact.addAttribute(attribute)
                        except:
                            self.log(Level.WARNING, "Error adding other Attribute" + list(metadata)[m] + "to the Artifact!")
                        
                
                #blackboard.postArtifact(artifact, ImageMetadataFileIngestModuleWithUIFactory.moduleName)
                
                blackboard.indexArtifact(artifact)
                
                # Fires an event to notify the UI and others that there is a new artifact
                # So that the UI updates and refreshes with the new artifacts when the module is executed
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                                 artId, None))
                
            #============================== end of IMAGE METADATA ANALYSIS ==============================#
            
            
            #============================== start of IMAGE METADATA FILTERING ==============================#
            
            # Different levels:
            #   - 1st level => basic one condition filter
            #   - 2nd level => "AND" filter ("" + and + "")
            #   - 3rd level => "OR" filter ("" + or + "")
            #   - 4th level => "NOT" filter (not + "")
            #   - TO DO: 5th level => "AND", "OR", "NOT" mixed filter
            
            validation = 0
            
            pattern_1 = "[a-zA-Z0-9]+"

            pattern_2 = "[a-zA-Z0-9]+\s(and)\s[a-zA-Z0-9]+"
            
            pattern_3 = "[a-zA-Z0-9]+\s(or)\s[a-zA-Z0-9]+"
            
            pattern_4 = "(not)\s[a-zA-Z0-9]+"
            
            wordToSearch = self.local_settings.getSetting("word_search")
            artifact2 = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            
            # 2nd LEVEL: "AND". 
            #   - We can include as many "and" as we want: Canon and iPhone and Jordi and ...    
            if (re.search(pattern_2, wordToSearch)):
                validation = 0
                output = re.split("\sand\s", wordToSearch) # Output is a list containing the words to search
                
                for x in output:
                    
                    for m in range(0, len(metadata)):
                        
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct evaluation 
                        # metadata_att is the str of each attribute                   
                        if type((list(metadata.values())[m])) is not str:
                            metadata_att = str(list(metadata.values())[m])
                        else:
                            metadata_att = list(metadata.values())[m]
                            
                        if x in metadata_att:
                            validation += 1
                            break
                        
                    if validation == len(output):
                        attribute2 = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                                                     ImageMetadataFileIngestModuleWithUIFactory.moduleName, wordToSearch)
                        artifact2.addAttribute(attribute2)
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                                         BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
                        break
                        
                            
            # 3rd LEVEL: "OR". 
            #   - We can include as many "or" as we want: Canon or iPhone or Jordi or ...          
            elif (re.search(pattern_3, wordToSearch)):
                validation = 0
                output = re.split("\sor\s", wordToSearch) # Output is a list containing the words to search
                
                for x in output:
                    
                    for m in range(0, len(metadata)):
                        
                        # Check the value of the metadata: if it is not a string, convert it to string for a correct evaluation 
                        # metadata_att is the str of each attribute                   
                        if type((list(metadata.values())[m])) is not str:
                            metadata_att = str(list(metadata.values())[m])
                        else:
                            metadata_att = list(metadata.values())[m]
                                       
                        if x in metadata_att:
                            validation += 1
                            
                    if validation > 0:
                        attribute2 = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                                                     ImageMetadataFileIngestModuleWithUIFactory.moduleName, wordToSearch)
                        artifact2.addAttribute(attribute2)
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                                         BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
                        break
                                  
            # 4th LEVEL: "NOT". 
            #   - We can only include one "not"
            elif (re.search(pattern_4, wordToSearch)):
                validation = 0
                output = re.sub("not\s", "", wordToSearch) # Output is a list containing the words to search
                    
                for m in range(0, len(metadata)):
                    
                    # Check the value of the metadata: if it is not a string, convert it to string for a correct evaluation 
                    # metadata_att is the str of each attribute                   
                    if type((list(metadata.values())[m])) is not str:
                        metadata_att = str(list(metadata.values())[m])
                    else:
                        metadata_att = list(metadata.values())[m]
                                   
                    if output in metadata_att:
                        validation += 1
                        
                if validation == 0:
                    attribute2 = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                                                 ImageMetadataFileIngestModuleWithUIFactory.moduleName, wordToSearch)
                    artifact2.addAttribute(attribute2)
                    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                                     BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
                
            # 1st LEVEL: One word. 
            #   - We can only include one word to search
            elif (re.search(pattern_1, wordToSearch)):
                validation = 0
                output = wordToSearch
                    
                for m in range(0, len(metadata)):
                    
                    # Check the value of the metadata: if it is not a string, convert it to string for a correct evaluation 
                    # metadata_att is the str of each attribute                   
                    if type((list(metadata.values())[m])) is not str:
                        metadata_att = str(list(metadata.values())[m])
                    else:
                        metadata_att = list(metadata.values())[m]
                                   
                    if output in metadata_att:
                        attribute2 = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                                                 ImageMetadataFileIngestModuleWithUIFactory.moduleName, wordToSearch)
                        artifact2.addAttribute(attribute2)
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                                         BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
                        break
                    
            else:
                
                self.log(Level.WARNING, "Incorrect filter's input!")
                
            
            
            #============================== end of IMAGE METADATA FILTERING ==============================#
            
            

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    def shutDown(self):
        # As a final part, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                str(self.filesAnalyzed) + " files analyzed")
        ingestServices = IngestServices.getInstance().postMessage(message)
        



#============================================================#
#                  -- PANEL RELATED CLASS --                 #
#============================================================#

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
        self.customizeComponents()

    
    #=============== start CheckBox Events ===============#
    
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
            
    def wordCheckBoxEvent(self, event):
        self.local_settings.setSetting("word_search", self.word_search.getText())
        
    def filterChekBoxEvent(self, event):
        if self.filter_checkbox.isSelected():
            self.local_settings.setSetting("filter", "true")
        else:
            self.local_settings.setSetting("filter", "false")
    
    #=============== end CheckBox Events ===============#
            

    def initComponents(self):
        #self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setLayout(None)
        
        title1 = JLabel("IMAGE METADATA ANALYZER")
        title1.setHorizontalAlignment(SwingConstants.LEFT)
        title1.setFont(Font("Tahoma", Font.BOLD, 14))
        title1.setBounds(0, 10, 300, 20)
        self.add(title1)
        
        label1 = JLabel("Select the type of Metadata you want to analyze:")
        label1.setHorizontalAlignment(SwingConstants.LEFT)
        label1.setFont(Font("Default", Font.PLAIN, 11))
        label1.setBounds(0, 40, 300, 20)
        self.add(label1)
        
        # EXIF checkbox
        self.exif_checkbox = JCheckBox("EXIF Metadata", actionPerformed=self.exifCheckBoxEvent)
        self.exif_checkbox.setBounds(5, 60, 110, 20)
        self.add(self.exif_checkbox)
        
        # IPTC checkbox
        self.iptc_checkbox = JCheckBox("IPTC Metadata", actionPerformed=self.iptcCheckBoxEvent)
        self.iptc_checkbox.setBounds(125, 60, 110, 20)
        self.add(self.iptc_checkbox)
        
        # XMP checkbox
        self.xmp_checkbox = JCheckBox("XMP Metadata", actionPerformed=self.xmpCheckBoxEvent)
        self.xmp_checkbox.setBounds(5, 80, 110, 20)
        self.add(self.xmp_checkbox)
        
        # Other checkbox
        self.other_checkbox = JCheckBox("Other", actionPerformed=self.otherCheckBoxEvent)
        self.other_checkbox.setBounds(125, 80, 110, 20)
        self.add(self.other_checkbox)
        
        
        label2 = JLabel("Select the type of image file you want to analyze:")
        label2.setHorizontalAlignment(SwingConstants.LEFT)
        label2.setFont(Font("Default", Font.PLAIN, 11))
        label2.setBounds(0, 110, 300, 20)
        self.add(label2)
        
        # JPG checkbox
        self.jpg_checkbox = JCheckBox("JPG (JPEG)", actionPerformed=self.jpgCheckBoxEvent)
        self.jpg_checkbox.setBounds(5, 130, 80, 20)
        self.add(self.jpg_checkbox)
        
        # PNG checkbox
        self.png_checkbox = JCheckBox("PNG", actionPerformed=self.pngCheckBoxEvent)
        self.png_checkbox.setBounds(100, 130, 80, 20)
        self.add(self.png_checkbox)
        
        # TIFF checkbox
        self.tiff_checkbox = JCheckBox("TIFF", actionPerformed=self.tiffCheckBoxEvent)
        self.tiff_checkbox.setBounds(195, 130, 80, 20)
        self.add(self.tiff_checkbox)
        
        # GIF checkbox
        self.gif_checkbox = JCheckBox("GIF", actionPerformed=self.gifCheckBoxEvent)
        self.gif_checkbox.setBounds(5, 150, 80, 20)
        self.add(self.gif_checkbox)
        
        # HEIC checkbox
        self.heic_checkbox = JCheckBox("HEIC", actionPerformed=self.heicCheckBoxEvent)
        self.heic_checkbox.setBounds(100, 150, 80, 20)
        self.add(self.heic_checkbox)
        
        title2 = JLabel("IMAGE METADATA FILTER")
        title2.setHorizontalAlignment(SwingConstants.LEFT)
        title2.setFont(Font("Tahoma", Font.BOLD, 14))
        title2.setBounds(0, 190, 300, 20)
        self.add(title2)
        
        label3 = JLabel("Write the filter you want to introduce and search it:")
        label3.setHorizontalAlignment(SwingConstants.LEFT)
        label3.setFont(Font("Default", Font.PLAIN, 11))
        label3.setBounds(0, 220, 300, 20)
        self.add(label3)
        
        label3_1 = JLabel("For example: Canon or iPhone")
        label3_1.setHorizontalAlignment(SwingConstants.LEFT)
        label3_1.setFont(Font("Default", Font.ITALIC, 8))
        label3_1.setBounds(0, 233, 300, 20)
        self.add(label3_1)
        
        self.word_search = JTextField()
        self.word_search.setBounds(5, 250, 220, 23)
        self.add(self.word_search)
        #self.word_search.setAction(actionPerformed=self.wordSearchTextField)
        #self.local_settings.setSetting("word_search", self.word_search.getText())
        
        self.word_search_button = JButton("Search!", actionPerformed=self.wordCheckBoxEvent)
        self.word_search_button.setBounds(230, 250, 80, 22)
        self.add(self.word_search_button)
        
        self.filter_checkbox = JCheckBox("Use only the Image Metadata Filter", actionPerformed=self.filterChekBoxEvent)
        self.filter_checkbox.setBounds(5, 280, 300, 20)
        self.add(self.filter_checkbox)
        

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
        
        # Mantain the GUI Filter box selected if selected before
        self.filter_checkbox.setSelected(self.local_settings.getSetting("filter") == "true")

    # Return the settings used
    def getSettings(self):
        return self.local_settings