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
from javax.swing import JCheckBox, JLabel
from javax.swing import BoxLayout
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
from java.lang import IllegalArgumentException

from neededLib.exiftool import ExifTool

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
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
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
        
         
        if file.getName().lower().endswith(".jpg"):
            
            self.log(Level.INFO, "Found a JPG file with path: " + file.getLocalAbsPath())
            #self.log(Level.INFO, "Found a JPG file with path: " + file.getUniquePath())
            self.filesAnalyzed += 1
            self.log(Level.INFO, "Files analyzed: " + str(self.filesAnalyzed))
            
            #if self.local_settings.getSetting("exif") == "true":
             #   self.filesAnalyzed += 1
                
            
            # Analyze the image metadata
            with ExifTool(PATH_MACOS) as et:   
                metadata = et.get_metadata(file.getLocalAbsPath())
                #metadata = et.get_metadata(file.getUniquePath())
                
            #for m in range(0, len(metadata)):
             #   if (list(metadata)[m] == "EXIF:Model"):
              #      camera_model = list(metadata.values())[m]
               #     self.filesAnalyzed += 1
                #    break
            
            # Use blackboard class to index blackboard artifacts for keyword search
            blackboard = Case.getCurrentCase().getServices().getBlackboard()
            
            # Creating a custom Artifact
            artId = blackboard.getOrAddArtifactType("TSK_IMAGE_METADATA", "Image Metadata Analyzer")
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
                        self.log(Level.INFO, "Error adding EXIF Attribute" + list(metadata)[m] + "to the Artifact!")
                
                        
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
                        self.log(Level.INFO, "Error adding IPTC Attribute" + list(metadata)[m] + "to the Artifact!")
                        
                        
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
                        self.log(Level.INFO, "Error adding XMP Attribute" + list(metadata)[m] + "to the Artifact!")
                
                # Add other metadata information found such as "File:", "Composite:", etc.
                if self.local_settings.getSetting("other") == "true":
                    
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
                        self.log(Level.INFO, "Error adding other Attribute" + list(metadata)[m] + "to the Artifact!")
                    
            
            # Use blackboard class to index blackboard artifacts for keyword search
            # blackboard = Case.getCurrentCase().getServices().getBlackboard()
            
            # Creating a custom Artifact
            # artId = blackboard.getOrAddArtifactType("TSK_IMAGE_METADATA", "Image Metadata Analyzer")
            # artifact = file.newArtifact(artId.getTypeID())
            
            # Creating new Attributes
            # attId = blackboard.getOrAddAttributeType("TSK_CAMERA_MODEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Camera Model")
            # attribute = BlackboardAttribute(attId, ImageMetadataFileIngestModuleWithUIFactory.moduleName, camera_model)
            
            # Adding the Attribute to the Artifact
            # try:  
              #  artifact.addAttribute(attribute)
            # except:
              #  self.log(Level.INFO, "Error adding Attribute to the Artifact!")
                    
            
            #blackboard.postArtifact(artifact, ImageMetadataFileIngestModuleWithUIFactory.moduleName)
            
            # Fires an event to notify the UI and others that there is a new artifact
            # So that the UI updates and refreshes with the new artifacts when the module is executed
            IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                                                                             BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
            

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    def shutDown(self):
        # As a final part, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ImageMetadataFileIngestModuleWithUIFactory.moduleName,
                str(self.filesAnalyzed) + " files analyzed")
        ingestServices = IngestServices.getInstance().postMessage(message)
        #pass



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
            

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        
        label1 = JLabel("Select the type of Metadata you want to analyze:")
        self.add(label1)
        
        # EXIF checkbox
        self.exif_checkbox = JCheckBox("EXIF Metadata", actionPerformed=self.exifCheckBoxEvent)
        self.add(self.exif_checkbox)
        
        # IPTC checkbox
        self.iptc_checkbox = JCheckBox("IPTC Metadata", actionPerformed=self.iptcCheckBoxEvent)
        self.add(self.iptc_checkbox)
        
        # XMP checkbox
        self.xmp_checkbox = JCheckBox("XMP Metadata", actionPerformed=self.xmpCheckBoxEvent)
        self.add(self.xmp_checkbox)
        
        # Other checkbox
        self.other_checkbox = JCheckBox("Other", actionPerformed=self.otherCheckBoxEvent)
        self.add(self.other_checkbox)
        
        label2 = JLabel("Select the type of image files you want to analyze:")
        self.add(label2)
        
        

    def customizeComponents(self):
        # Mantain the GUI EXIF box selected if selected before
        self.exif_checkbox.setSelected(self.local_settings.getSetting("exif") == "true")
        
        # Mantain the GUI IPTC box selected if selected before
        self.iptc_checkbox.setSelected(self.local_settings.getSetting("iptc") == "true")
        
        # Mantain the GUI XMP box selected if selected before
        self.xmp_checkbox.setSelected(self.local_settings.getSetting("xmp") == "true")
        
        # Mantain the GUI Other box selected if selected before
        self.other_checkbox.setSelected(self.local_settings.getSetting("other") == "true")

    # Return the settings used
    def getSettings(self):
        return self.local_settings