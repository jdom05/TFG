#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Apr 30 20:10:07 2021

@author: JORDI
"""


from java.util.logging import Level

from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.autopsy.ingest import ModuleDataEvent



def startUpLogs(self):
    
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
    
# Write logs and post them on the User Interface to inform the user of any inconvenience or interesting information 
def postInformationForTheUser(self, moduleName, levelType, messageType, sentence):
    
    self.log(levelType, sentence)
    
    message = IngestMessage.createMessage(messageType, moduleName, sentence)    
    ingestServices = IngestServices.getInstance().postMessage(message)
    

# Check the value of the metadata: if it is not a string, convert it to string for a correct printing 
# metadataValue -> corresponds to each value/attribute of the metadata analyzed by the exiftool library
# Returns the string of each metadata attribute
def metadataToString(metadataValue):

    if type(metadataValue) is not str:
        metadata_att = str(metadataValue)
    else:
        metadata_att = metadataValue
        
    return metadata_att
    

# Add the new Attribute with the value of the metadata analyzed
# metadataAttributeName -> corresponds to each name/title of the metadata analyzed by the exiftool library
# metadataAttribute -> is the string of the value/attribute of each metadata
def addNewMetadataAttribute(blackboard, artifact, artId, moduleName, metadataAttributeName, metadataAttribute):
    
    attId = blackboard.getOrAddAttributeType("TSK_" + metadataAttributeName,
                                             BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, metadataAttributeName)
    attribute = BlackboardAttribute(attId, moduleName, metadataAttribute)
    
    # Adding the Attribute to the Artifact
    artifact.addAttribute(attribute)  
    # Error Test
    #artifact.addAttribute(None)
    
    blackboard.indexArtifact(artifact)
                
    # Fires an event to notify the UI and others that there is a new artifact
    # So that the UI updates and refreshes with the new artifacts when the module is executed
    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(moduleName, artId, None))
    

# Add a new Attribute in the File Interesting Hit Artifact
# artifact -> File Interesting Hit Artifact
# moduleName -> name of the module
# attributeName -> name of the attribute we want to visualize on the blackboard
def addInterestingFileHitAttribute(artifact, moduleName, attributeName):
    
    attribute = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), moduleName, attributeName)
    
    artifact.addAttribute(attribute)
    
    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(moduleName, BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
    
    
    
    
    
    
    
    
    