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
# Microsoft [CVRF] Parser                                    #
# Written by Tyler Reguly (treguly@tripwire.com)             #
##############################################################

#### CONFIGURATION INFORMATION ####

ms_api_key = 'fcf30364ef07476aa8fea0ce769e0529'
item_id = '2016-Nov'

###################################

# stdlib imports
import sys
import lxml.html as lhtml

#CSBF Imports
import CSBFGenerator
import CVRFParser

url = "https://api.msrc.microsoft.com/cvrf/%s?api-version=2016-08-01" % (item_id)
headers = {'api-key': ms_api_key}


try:
    cvrf = CVRFParser.CVRFParser(source = 'http', doc = url, headers = headers)
except CVRFParser.etree.XMLSyntaxError:
    print 'Invalid XML'
    sys.exit(-1)
    
bulletin_report = CSBFGenerator.CSBFBulletin()

bulletin_report.bulletin_id = cvrf.DocumentTracking.Identification.ID
bulletin_report.bulletin_title = cvrf.DocumentTitle
bulletin_report.cves = [vuln.CVE for vuln in cvrf.Vulnerability]
bulletin_report.industry_ids = [(ref.Description, ref.URL) for ref in cvrf.DocumentReferences]
bulletin_report.description = [(notes.Type, lhtml.fromstring(notes.Text).text_content()) for notes in cvrf.DocumentNotes]

vuln_reports = []
for vuln in cvrf.Vulnerability:
    report = CSBFGenerator.CSBFVuln()
    report.cve = vuln.CVE
    if vuln.Notes: report.description = [(notes.Type, lhtml.fromstring(notes.Text).text_content()) for notes in vuln.Notes]
    if vuln.References: report.related_links = [(ref.Description, ref.URL) for ref in vuln.References]
    if vuln.Acknowledgements: report.acknowledgement = [('Microsoft', ack.Name) for ack in vuln.Acknowledgements]
    vuln_reports.append(report)
    

bulletin_report.report
for vuln in vuln_reports:
    vuln.report


