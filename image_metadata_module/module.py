#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 23 16:14:16 2021

@author: JORDI
"""

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard

from neededLib.exiftool import ExifTool

PATH_WINDOWS = "C:\WINDOWS\exiftool.exe" #WINDOWS path to the exiftool executable
PATH_MACOS = "/usr/local/bin/exiftool" #MACOS path to the exiftool executable

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
class ImageMetadataFileIngestModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Image Metadata analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Autopsy module for automated analysis of image metadata."

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return ImageMetadataFileIngestModule()


# File-level ingest module.  One gets created per thread.
# Looks at the attributes of the passed in file.
class ImageMetadataFileIngestModule(FileIngestModule):

    _logger = Logger.getLogger(ImageMetadataFileIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.filesAnalyzed = 0
        self.filesFound = 0

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):
        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK
        
         
        if file.getName().lower().endswith(".jpg"):
            
            self.log(Level.INFO, "Found a JPG file with path: " + file.getLocalAbsPath())
            #self.log(Level.INFO, "Found a JPG file with path: " + file.getUniquePath())
            self.filesFound += 1
            
            # Analyze the image metadata
            with ExifTool(PATH_MACOS) as et:   
                metadata = et.get_metadata(file.getLocalAbsPath())
                #metadata = et.get_metadata(file.getUniquePath())
                
            for m in range(0, len(metadata)):
                if list(metadata)[m] == "EXIF:Model":
                    camera_model = list(metadata.values())[m]
                    self.filesAnalyzed += 1
                    break
            
            # Use blackboard class to index blackboard artifacts for keyword search
            blackboard = Case.getCurrentCase().getServices().getBlackboard()
            
            # Creating a custom Artifact
            
            artId = blackboard.getOrAddArtifactType("TSK_IMAGE_METADATA", "Image Metadata Analyzer")
            
            artifact = file.newArtifact(artId.getTypeID())
            
            
            # Creating new attributes
            
            attId = blackboard.getOrAddAttributeType("TSK_CAMERA_MODEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Camera Model")
            
            attribute = BlackboardAttribute(attId, ImageMetadataFileIngestModuleFactory.moduleName, camera_model)
            
            try:  
                artifact.addAttribute(attribute)
            except:
                self.log(Level.INFO, "Error adding Attribute to the Artifact!")
                    
            
            #blackboard.postArtifact(artifact, ImageMetadataFileIngestModuleFactory.moduleName)
            
            # Fires an event to notify the UI and others that there is a new artifact
            # So that the UI updates and refreshes with the new artifacts when the module is executed
            IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ImageMetadataFileIngestModuleFactory.moduleName,
                                                                             BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
            

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ImageMetadataFileIngestModuleFactory.moduleName,
                str(self.filesFound) + " image files found & " + str(self.filesAnalyzed) + " JPG files analyzed")
        ingestServices = IngestServices.getInstance().postMessage(message)
