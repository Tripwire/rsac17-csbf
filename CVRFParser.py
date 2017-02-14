###############################################################################
# 
# Copyright (c) 2017, Tripwire, Inc.
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###############################################################################
##############################################################
# Common Vulnerability Reporting Framework [CVRF] Parser     #
# Written by Tyler Reguly (treguly@tripwire.com)             #
##############################################################

# IMPORTS

import urllib2
import json
import xmltodict
import lxml.etree as etree

class DocumentPublisher(object):
    
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__type = self.data.get('@Type', '')
        self.__vendor_id = self.data.get('@VendorID', '')
        self.__contact_details = self.data.get('ContactDetails', '')
        self.__issuing_authority = self.data.get('IssuingAuthority', '')
        
 
    # PROPERTIES
        
    @property
    def Type(self):
        return self.__type
    
    @property
    def VendorID(self):
        return self.__vendor_id
    
    @property
    def ContactDetails(self):
        return self.__contact_details
    
    @property
    def IssuingAuthority(self):
        return self.__issuing_authority
        
class DocumentTracking(object):
    
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__status = self.data.get('Status', '')
        self.__version = self.data.get('Version', '')
        self.__initial_release_data = self.data.get('InitialReleaseDate', '')
        self.__current_release_date = self.data.get('CurrentReleaseDate', '')
        
        # Setup CVRF Containers
        self.Identification = DTIdentification(self.data.get('Identification', {}))
        self.RevisionHistory = DTRevisionHistory(self.data.get('RevisionHistory', {})).Revisions
        self.Generator = DTGenerator(self.data.get('Generator', {}))
        
    # PROPERTIES
    @property
    def Status(self):
        return self.__status
    
    @property
    def Version(self):
        return self.__version
    
    @property
    def InitialReleaseDate(self):
        return self.__initial_release_date
    
    @property
    def CurrentReleaseDate(self):
        return self.__current_release_date

class DTIdentification(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__id = self.data.get('ID', '')
        self.__aliases = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('Alias', []), list):
            for item in self.data.get('Alias', {}):
                self.__aliases.append(DTIAlias(item))
        else:
            self.__aliases = [DTIAlias(self.data['Alias'])]
            
    # PROPERTIES
    @property
    def ID(self):
        return self.__id
    
    @property
    def Aliases(self):
        return self.__aliases

class DTRevisionHistory(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__revisions = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('Revision', []), list):
            for item in self.data.get('Revision', []):
                self.__revisions.append(DTRHRevision(item))
        else:
            self.__revisions = [DTRHRevision(self.data['Revision'])]
            
                
    # PROPERTIES
    @property
    def Revisions(self):
        return self.__revisions

class DTGenerator(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__engine = self.data.get('Engine', '')
        self.__date = self.data.get('Date', '')
        
        # Setup CVRF Containers
                
    # PROPERTIES
    @property
    def Engine(self):
        return self.__engine
    
    @property
    def Date(self):
        return self.__date

class DTRHRevision(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__number = self.data.get('Number', '')
        self.__date = self.data.get('Date', '')
        self.__description = self.data.get('Description', '')
        
        # Setup CVRF Containers
                
    # PROPERTIES
    @property
    def Number(self):
        return self.__number
    
    @property
    def Date(self):
        return self.__date
    
    @property
    def Description(self):
        return self.__description   

class DTIAlias(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Alias = self.data

class Notes(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__notes = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('Note', []), list):
            for item in self.data.get('Note', []):
                self.__notes.append(Note(item))
        else:
            self.__notes = [Note(self.data['Note'])]
            
    # PROPERITES
    @property
    def Notes(self):
        return self.__notes
                
class Note(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Title = self.data.get('@Title', '')
        self.Type = self.data.get('@Type', '')
        self.Ordinal = self.data.get('@Ordinal', '')
        self.Audience = self.data.get('@Audience', '')
        self.Text = self.data.get('#text', '')

class References(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__references = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('Reference', []), list):
            for item in self.data.get('Reference', []):
                self.__references.append(Reference(item))
        else:
            self.__references = [Reference(self.data['Reference'])]
            
    # PROPERITES
    @property
    def References(self):
        return self.__references
    
class Reference(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Type = self.data.get('@Type', '')
        self.URL = self.data.get('URL', '')
        self.Description = self.data.get('Description', '')

class AggregateSeverity(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__namespace = self.data.get('@Namespace', '')
        self.__text = self.data.get('#text', '')
        
    # PROPERTIES
    @property
    def Namespace(self):
        return self.__namespace
    
    @property
    def Text(self):
        return self.__text
        
class Acknowledgements(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__acknowledgements = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('Acknowledgement', []), list):
            for item in self.data.get('Acknowledgement', []):
                self.__acknowledgements.append(Acknowledgement(item))
        else:
            self.__acknowledgements = [Acknowledgement(self.data['Acknowledgement'])]
            
    # PROPERITES
    @property
    def Acknowledgements(self):
        return self.__acknowledgements
    
class Acknowledgement(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Description = self.data.get('Description', '')
        self.__names == []
        self.__organizations = []
        self.__urls = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('Name', []), list):
            for item in self.data.get('Name', []):
                self.__names.append(AName(item))
        else:
            self.__names = [AName(self.data['Name'])]
        if isinstance(self.data.get('Organization', []), list):
            for item in self.data.get('Organization', []):
                self.__organizations.append(AOrganization(item))
        else:
            self.__organizations = [AOrganization(self.data['Organization'])]
        if isinstance(self.data.get('URL', []), list):
            for item in self.data.get('URL', []):
                self.__urls.append(AURL(item))
        else:
            self.__urls = [AURL(self.data['URL'])]            
        
    # PROPERTIES
    @property
    def Names(self):
        return self.__names
    
    @property
    def Organizations(self):
        return self.__organizations
    
    @property
    def URLs(self):
        return self.__urls
    
class AName(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Name = self.data

class AOrganization(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Organization = self.data

class AURL(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.URL = self.data

class ProductTree(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__full_product_names = []
        self.__branches = []
        self.__relationships = []
        self.__product_groups = []
        
        
        # Setup CVRF Containers
        if isinstance(self.data.get('FullProductName', []), list):
            for item in self.data.get('FullProductName', []):
                self.__full_product_names.append(PTFullProductName(item))
        else:
            self.__full_product_names = [PTFullProductName(self.data['FullProductName'])]
        if isinstance(self.data.get('Branch', []), list):
            for item in self.data.get('Branch', []):
                self.__branches.append(PTBranch(item))
        else:
            self.__branches = [PTBranch(self.data['Branch'])]
        if isinstance(self.data.get('Relationship', []), list):
            for item in self.data.get('Relationship', []):
                self.__relationships.append(PTRelationship(item))
        else:
            self.__relationships = [PTRelationship(self.data['Relationship'])]
        if isinstance(self.data.get('ProductGroups', []), list):
            for item in self.data.get('ProductGroups', []):
                self.__product_groups.append(PTProductGroups(item))
        else:
            self.__product_groups = [PTProductGroups(self.data['ProductGroups'])]            
            
    # PROPERITES
    @property
    def FullProductNames(self):
        return self.__full_product_names    
 
    @property
    def Branches(self):
        return self.__branches
    
    @property
    def Relationships(self):
        return self.__relationships
    
class PTBranch(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Name = data.get('@Name', '')
        self.Type = data.get('@Type', '')
        self.__full_product_names = []
        self.__branches = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('FullProductName', []), list):
            for item in self.data.get('FullProductName', []):
                self.__full_product_names.append(PTFullProductName(item))
        else:
            self.__full_product_names = [PTFullProductName(self.data['FullProductName'])]
        if isinstance(self.data.get('Branch', []), list):
            for item in self.data.get('Branch', []):
                self.__branches.append(PTBranch(item))
        else:
            self.__branches = [PTBranch(self.data['Branch'])]
            
    # PROPERITES
    @property
    def FullProductNames(self):
        return self.__full_product_names    
 
    @property
    def Branches(self):
        return self.__branches
        
class PTRelationship(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.ProductReference = self.data.get('@ProductReference', '')
        self.RelationshipType = self.data.get('@RelationshipType', '')
        self.RelatesToProductReference = self.data.get('@RelatesToProductReference', '')
        self.__full_product_names = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('FullProductName', []), list):
            for item in self.data.get('FullProductName', []):
                self.__full_product_names.append(PTFullProductName(item))
        else:
            self.__full_product_names = [PTFullProductName(self.data['FullProductName'])]
            
    # PROPERITES
    @property
    def FullProductNames(self):
        return self.__full_product_names
    
class PTProductGroups(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__groups = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('Group', []), list):
            for item in self.data.get('Group', []):
                self.__groups.append(PTGroup(item))
        else:
            self.__groups = [PTGroup(self.data['Group'])]
            
    # PROPERITES
    @property
    def Groups(self):
        return self.__groups 
    
class PTFullProductName(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.ProductID = data.get('@ProductID', '')
        self.CPE = data.get('@CPE', '')
        self.Text = data.get('#text', '')
        
class PTGroup(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.GroupID = data.get('@GroupID', '')
        self.Description = data.get('Description', '')
        self.ProductIDs = self.data.get('ProductID', []) if isinstance(self.data.get('ProductID', []), list) else [self.data.get('ProductID', '')]
    
class Vulnerabilities(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.__vulnerabilities = []
        
        # Setup CVRF Containers
        if isinstance(self.data, list):
            for item in self.data:
                self.__vulnerabilities.append(Vulnerability(item))
        else:
            self.__vulnerabilities = [Vulnerability(self.data)]
            
    # PROPERTIES
    @property
    def Vulnerabilities(self):
        return self.__vulnerabilities
    
class Vulnerability(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Ordinal = self.data.get('@Ordinal', '')
        self.Title = self.data.get('Title', '')
        self.ID = self.data.get('ID', '')
        self.DiscoveryDate = self.data.get('DiscoveryDate', '')
        self.ReleaseDate = self.data.get('ReleaseDate', '')
        self.CVE = self.data.get('CVE', '')
        self.Acknowledgements = Acknowledgements(self.data.get('Acknowledgements', {})).Acknowledgements
        self.References = References(self.data.get('References', {})).References
        self.Notes = Notes(self.data.get('Notes', {})).Notes
        self.CWEs = self.data.get('CWE', []) if isinstance(self.data.get('CWE', []), list) else [self.data.get('CWE', '')]
        self.__involvements = []
        self.__product_statuses = []
        self.__threats = []
        self.__cvss_score_sets = []
        self.__remediations = []
        
        # Setup CVRF Containers
        if isinstance(self.data.get('Involvements', []), list):
            for item in self.data.get('Involvements', []):
                self.__involvements.append(Involvement(item))
        else:
            self.__involvements = [Involvement(self.data['Involvements'])]
        
        if isinstance(self.data.get('ProductStatuses', []), list):
            for item in self.data.get('ProductStatuses', []):
                self.__product_statuses.append(Status(item))
        else:
            self.__product_statuses = [Status(self.data['ProductStatuses'])]
        
        if isinstance(self.data.get('Threats', []), list):
            for item in self.data.get('Threats', []):
                self.__threats.append(Threat(item))
        else:
            self.__threats = [Threat(self.data['Threats'])]
        
        if isinstance(self.data.get('CVSSScoreSets', []), list):
            for item in self.data.get('CVSSScoreSets', []):
                self.__cvss_score_sets.append(ScoreSet(item))
        else:
            self.__cvss_score_sets = [ScoreSet(self.data['CVSSScoreSets'])]
        
        if isinstance(self.data.get('Remediations', []), list):
            for item in self.data.get('Remediations', []):
                self.__remediations.append(Remediation(item))
        else:
            self.__remediations = [Remediation(self.data['Remediations'])]
            
    # PROPERTIES
    @property
    def Involvements(self):
        return self.__involvements
    
    @property
    def Involvements(self):
        return self.__product_statuses
 
    @property
    def Involvements(self):
        return self.__threats
 
    @property
    def Involvements(self):
        return self.__cvss_score_sets
 
    @property
    def Involvements(self):
        return self.__remediations
     
class Involvement(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Party = self.data.get('@Party', '')
        self.Status = self.data.get('@Status', '')
        self.Description = self.data.get('Description', '')
        
class Status(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Type = self.data.get('@Type', '')
        self.ProductIDs = self.data.get('ProductID', []) if isinstance(self.data.get('ProductID', []), list) else [self.data.get('ProductID', '')]
    
class Threat(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Type = self.data.get('@Type', '')
        self.Date = self.data.get('@Date', '')
        self.Description = self.data.get('Description', '')
        self.ProductIDs = self.data.get('ProductID', []) if isinstance(self.data.get('ProductID', []), list) else [self.data.get('ProductID', '')]
        self.GroupIDs = self.data.get('GroupID', []) if isinstance(self.data.get('GroupID', []), list) else [self.data.get('GroupID', '')]
  
class ScoreSet(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.BaseScore = self.data.get('BaseScore', '')
        self.Vector = self.data.get('Vector', '')
        self.TemporalScore = self.data.get('TemporalScore', '')
        self.EnvironmentalScore = self.data.get('EnvironmentalScore', '')
        self.ProductIDs = self.data.get('ProductID', []) if isinstance(self.data.get('ProductID', []), list) else [self.data.get('ProductID', '')]
              
class Remediation(object):
    def __init__(self, data):
        self.data = data if data else {}
        
        # Setup CVRF Strings
        self.Type = self.data.get('@Type', '')
        self.Entitlement = self.data.get('Entitlement', '')
        self.URL = self.data.get('URL', '')
        self.Description = self.data.get('Description', '')
        self.ProductIDs = self.data.get('ProductID', []) if isinstance(self.data.get('ProductID', []), list) else [self.data.get('ProductID', '')]
        self.GroupIDs = self.data.get('GroupID', []) if isinstance(self.data.get('GroupID', []), list) else [self.data.get('GroupID', '')]

class CVRFParser(object):
    
    def __init__(self, source = 'file', doc = '', headers = ''):
        if source == 'http':
            self.url = doc
            self.headers = headers
            self.cvrf_data = self.load_results(self.get_page(self.url, self.headers))
        else:
            self.file = doc
            self.cvrf_data = self.load_results(self.file)
        
        # Setup CVRF Strings
        self.__document_title = self.cvrf_data.get('DocumentTitle', '')
        self.__document_type = self.cvrf_data.get('DocumentType', '')
        self.__document_distribution = self.cvrf_data.get('DocumentDistribution', '')
        
        
        # Setup CVRF Containers
        self.DocumentPublisher = DocumentPublisher(self.cvrf_data.get('DocumentPublisher', {}))
        self.DocumentTracking = DocumentTracking(self.cvrf_data.get('DocumentTracking', {}))
        self.DocumentNotes = Notes(self.cvrf_data.get('DocumentNotes', {})).Notes
        self.DocumentReferences = References(self.cvrf_data.get('DocumentReferences', {})).References
        self.AggregateSeverity = AggregateSeverity(self.cvrf_data.get('AggregateSeverity', {}))
        self.Acknowledgements = Acknowledgements(self.cvrf_data.get('Acknowledgements', {}))
        self.ProductTree = ProductTree(self.cvrf_data.get('ProductTree', {}))
        self.Vulnerability = Vulnerabilities(self.cvrf_data.get('Vulnerability', [])).Vulnerabilities
           
    # METHODS    

    def load_results(self, results, type='xml'):
        if type == 'json':
            return json.loads(results)[0]
        else:
            #Hack to normalize Microsoft CVRF Data
            remove_namespaces = {
                'cvrf': None,
                'prod': None,
                'vuln': None
            }
            dirty_result = etree.fromstring(results)
            for elem in dirty_result.xpath('//*[attribute::xml:lang]'):
                elem.attrib.pop('{http://www.w3.org/XML/1998/namespace}lang')
            clean_result = etree.tostring(dirty_result)
            #End Hack
            return xmltodict.parse(clean_result, namespaces=remove_namespaces)['cvrfdoc']
        
    def get_page(self, url, headers):
        opener = urllib2.build_opener(urllib2.HTTPHandler())
        urllib2.install_opener(opener)
        req = urllib2.Request(url, None, headers)
        response = urllib2.urlopen(req).read()
        return response

    # PROPERTIES

    @property
    def DocumentTitle(self):
        return self.__document_title
    
    @property
    def DocumentType(self):
        return self.__document_type
    
    @property
    def DocumentDistribution(self):
        return self.__document_distribution